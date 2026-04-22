"""CRA export service — build ZIP package with all compliance artifacts."""

from __future__ import annotations

import hashlib
import json
import logging
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from django.conf import settings as django_settings
from django.utils.text import slugify

from sbomify.apps.compliance.models import (
    CRAExportPackage,
    CRAGeneratedDocument,
)
from sbomify.apps.compliance.services._manufacturer_policy import (
    is_placeholder_manufacturer as _is_placeholder_manufacturer,
)
from sbomify.apps.compliance.services._reference_data import (
    read_harmonised_standards_bytes,
)
from sbomify.apps.compliance.services.oscal_service import serialize_assessment_results
from sbomify.apps.core.models import Component
from sbomify.apps.core.object_store import S3Client
from sbomify.apps.core.services.results import ServiceResult
from sbomify.apps.sboms.models import SBOM
from sbomify.apps.teams.services.contacts import get_manufacturer

if TYPE_CHECKING:
    from sbomify.apps.compliance.models import CRAAssessment
    from sbomify.apps.core.models import User

logger = logging.getLogger(__name__)

# Map document kinds to their paths inside the ZIP
_DOC_PATH_MAP: dict[str, str] = {
    "vdp": "documents/vulnerability-disclosure-policy.md",
    "risk_assessment": "documents/risk-assessment.md",
    "user_instructions": "documents/user-instructions.md",
    "decommissioning_guide": "documents/secure-decommissioning.md",
    "security_txt": "security.txt",
    "early_warning": "article-14/early-warning-template.md",
    "full_notification": "article-14/vulnerability-notification-template.md",
    "final_report": "article-14/final-report-template.md",
    "declaration_of_conformity": "declaration-of-conformity.md",
}

# CRA Annex references for manifest
_DOC_CRA_REF: dict[str, str] = {
    "vdp": "Annex I, Part II, §5-6",
    "risk_assessment": "Annex VII, §3",
    "user_instructions": "Annex II",
    "decommissioning_guide": "Annex I, Part I, §13",
    "security_txt": "RFC 9116 / BSI TR-03183-3",
    "early_warning": "Article 14 (≤24h)",
    "full_notification": "Article 14 (≤72h)",
    "final_report": "Article 14 (≤14d/1mo)",
    "declaration_of_conformity": "Article 28, Annex V",
}

# SBOM format → file extension for ZIP packaging
_FORMAT_EXT_MAP: dict[str, str] = {"cyclonedx": "cdx.json", "spdx": "spdx.json"}

# Single source of truth for the bundle's manifest schema version.
# Bump here; the integrity README and the manifest body both read from
# this constant so they can't drift. 1.0 was the original CRA export
# scaffolding; 1.1 added manufacturer.is_placeholder and the integrity
# block; bump to 1.2+ on the next schema change.
_MANIFEST_FORMAT_VERSION = "1.1"


def _signature_readme_section(signed: bool, provider: str | None) -> str:
    """Return the "About signatures" section of INTEGRITY.md.

    When a signature side-car was produced at export time (issue #906),
    describe how to verify it; otherwise keep the pre-existing guidance
    about applying a downstream signature. Both branches terminate the
    INTEGRITY.md — callers concatenate this at the end.
    """
    if signed:
        provider_label = {
            "sigstore_keyless": "a Sigstore keyless signature (Fulcio-issued ephemeral certificate)",
        }.get(provider or "", f"a {provider or 'configured'} signature")
        return (
            "## 3. Bundle signature\n\n"
            f"This bundle ships with {provider_label}. The signature is "
            "delivered as a side-car object alongside the ZIP — the download "
            "endpoint returns a second presigned URL ending in `.zip.sig` "
            "whose response body is the Sigstore bundle (JSON). Verify with:\n\n"
            "```sh\n"
            "cosign verify-blob \\\n"
            "  --bundle cra-package-*.zip.sig \\\n"
            "  --certificate-identity '<signing-identity>' \\\n"
            "  --certificate-oidc-issuer '<oidc-issuer>' \\\n"
            "  cra-package-*.zip\n"
            "```\n\n"
            "sbomify does not embed the bundle signature inside the ZIP — "
            "keeping it external preserves verifiable provenance across "
            "repackaging.\n"
        )
    return (
        "## 3. About signatures\n\n"
        "sbomify does not sign the bundle itself. Operators who need a "
        "stronger integrity / provenance guarantee for regulatory filings "
        "should sign the whole ZIP downstream with `cosign sign-blob` "
        "or `gpg --detach-sign` and distribute the detached signature "
        "alongside the bundle. The self-hash above bounds the manifest's "
        "integrity; a downstream signature bounds the whole package.\n\n"
        "To produce a signature automatically on every export, enable "
        "cosign / Sigstore signing in the team's compliance settings "
        "(issue #906).\n"
    )


def _integrity_readme(manifest_sha256: str, *, signed: bool = False, provider: str | None = None) -> str:
    """Human-readable bundle verification guide embedded in the export.

    The commands below are tested end-to-end against the real bundle
    layout — running them from the extracted package root (the folder
    named ``cra-package-<product-slug>/`` inside the ZIP) produces
    ``manifest.json: OK`` and ``<path>: OK`` for every file listed in
    the manifest's ``files`` array.
    """
    return (
        "# Bundle Integrity\n\n"
        f"Manifest `format_version` **{_MANIFEST_FORMAT_VERSION}** — changes vs 1.0 (shipped in\n"
        "the initial CRA export scaffolding):\n\n"
        "- `manufacturer.is_placeholder: bool` — flags when the team\n"
        "  profile still carries a stub name. Downstream consumers can\n"
        "  reject bundles where this is `true` to keep invalid DoCs\n"
        "  from being signed (Annex V item 2).\n"
        "- `integrity` block — self-describes the hash algorithm and\n"
        "  the companion files (`metadata/manifest.sha256`,\n"
        "  `metadata/INTEGRITY.md`). Old consumers that read\n"
        "  `format_version: 1.0` should ignore unknown keys.\n\n"
        "This CRA export bundle ships with two integrity primitives:\n\n"
        "- `metadata/manifest.json` — per-file SHA-256 hashes for every "
        "artefact listed in its `files` array. `metadata/manifest.json`, "
        "`metadata/manifest.sha256`, and this `metadata/INTEGRITY.md` are "
        "NOT listed (they are the integrity primitives themselves — "
        "listing them would be circular).\n"
        "- `metadata/manifest.sha256` — SHA-256 of `metadata/manifest.json` "
        "itself, so the manifest cannot be tampered with without "
        "detection.\n\n"
        "## 1. Verifying the manifest\n\n"
        "Run from the extracted bundle root (the `cra-package-<slug>/` "
        "directory inside the ZIP):\n\n"
        "```sh\n"
        "sha256sum -c metadata/manifest.sha256\n"
        "```\n\n"
        "Expected output: `metadata/manifest.json: OK`.\n\n"
        f"Expected digest (from `metadata/manifest.sha256`): `{manifest_sha256}`\n\n"
        "## 2. Verifying every individual artefact\n\n"
        "Again from the extracted bundle root:\n\n"
        "```sh\n"
        'jq -r \'.files[] | "\\(.sha256)  \\(.path | sub("^cra-package-[^/]*/"; ""))"\' \\\n'
        "  metadata/manifest.json | sha256sum -c -\n"
        "```\n\n"
        "Each file in the manifest prints `<path>: OK`. A non-zero exit "
        "code or any `FAILED` entry means the bundle has been modified "
        "since export. The `jq` `sub` expression strips the "
        "`cra-package-<slug>/` prefix so `sha256sum` resolves paths "
        "against the current working directory (the bundle root).\n\n"
        + _signature_readme_section(signed=signed, provider=provider)
    )


def _article_14_reporting_readme() -> str:
    """Article 14 deadlines + ENISA Single Reporting Platform pointers."""
    return (
        "# CRA Article 14 — Reporting Obligations\n\n"
        "Article 14 of Regulation (EU) 2024/2847 requires manufacturers to "
        "notify the competent CSIRT and ENISA when they become aware of an "
        "actively exploited vulnerability or a severe incident. **The "
        "reporting obligations apply from 2026-09-11**; until then, "
        "submissions are voluntary.\n\n"
        "## Deadlines\n\n"
        "| Deadline | Requirement | Template |\n"
        "| --- | --- | --- |\n"
        "| ≤24 h | Early warning: what, affected Member States, malicious?"
        " | `early-warning-template.md` |\n"
        "| ≤72 h | Vulnerability / incident notification with corrective"
        " measures taken | `vulnerability-notification-template.md` |\n"
        "| ≤14 d | Final report (vulnerability — after corrective measure"
        " applied) | `final-report-template.md` |\n"
        "| ≤1 mo | Final report (severe incident)"
        " | `final-report-template.md` |\n\n"
        "## Submission channel\n\n"
        "Article 16 designates ENISA to operate the Single Reporting Platform "
        "(SRP). The SRP consumes the notifications above and routes them to "
        "the competent CSIRTs automatically. Submission interface:\n\n"
        "- EC portal: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting\n\n"
        "sbomify does not yet auto-submit on the operator's behalf — templates "
        "are provided for manual filing. An automated pipeline will land once "
        "the SRP technical interface is publicly documented (tracked against "
        "the 2026-09-11 obligation date).\n"
    )


def _get_generated_doc_content(doc: CRAGeneratedDocument, s3_client: S3Client | None = None) -> bytes | None:
    """Fetch document content from S3."""
    try:
        if s3_client is None:
            s3_client = S3Client("DOCUMENTS")
        return s3_client.get_file_data(django_settings.AWS_DOCUMENTS_STORAGE_BUCKET_NAME, doc.storage_key)
    except Exception:
        logger.exception("Failed to fetch document %s from S3", doc.storage_key)
        return None


def _get_sbom_content(sbom: SBOM, s3_client: S3Client | None = None) -> bytes | None:
    """Fetch SBOM content from S3."""
    if not sbom.sbom_filename:
        return None
    try:
        if s3_client is None:
            s3_client = S3Client("SBOMS")
        return s3_client.get_sbom_data(sbom.sbom_filename)
    except Exception:
        logger.exception("Failed to fetch SBOM %s from S3", sbom.sbom_filename)
        return None


def build_export_package(
    assessment: CRAAssessment,
    user: User,
) -> ServiceResult[CRAExportPackage]:
    """Build a ZIP package containing all CRA compliance artifacts.

    ZIP structure:
        cra-package-{product-slug}/
        ├── declaration-of-conformity.md
        ├── oscal/
        │   ├── catalog.json
        │   └── assessment-results.json
        ├── sboms/
        │   └── {component-slug}.{ext}
        ├── documents/
        │   ├── vulnerability-disclosure-policy.md
        │   ├── risk-assessment.md
        │   ├── user-instructions.md
        │   └── secure-decommissioning.md
        ├── security.txt
        ├── article-14/
        │   ├── early-warning-template.md
        │   ├── vulnerability-notification-template.md
        │   └── final-report-template.md
        └── metadata/
            └── manifest.json
    """
    product = assessment.product
    # Mirror the presigned-URL filename convention: fall back to the
    # product id when slugify(name) returns empty (e.g. a name made
    # entirely of punctuation). Without this fallback, the bundle root
    # would be ``cra-package-/`` and every INTEGRITY.md command that
    # references ``cra-package-<slug>/`` would leave the slug segment
    # blank and confuse auditors.
    prefix = f"cra-package-{slugify(product.name) or product.id}"
    import tempfile

    manifest_files: list[dict[str, str]] = []
    # Spool to disk if ZIP exceeds 10MB to avoid OOM on large products
    buf = tempfile.SpooledTemporaryFile(max_size=10 * 1024 * 1024)

    # Create S3 clients once for reuse across all fetches
    docs_s3 = S3Client("DOCUMENTS")
    sboms_s3 = S3Client("SBOMS")

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. OSCAL catalog
        catalog_json = json.dumps(assessment.oscal_assessment_result.catalog.catalog_json, indent=2)
        catalog_bytes = catalog_json.encode("utf-8")
        _write_to_zip(zf, f"{prefix}/oscal/catalog.json", catalog_bytes, manifest_files, "OSCAL Catalog")

        # 2. OSCAL assessment results
        ar_json = serialize_assessment_results(assessment.oscal_assessment_result)
        ar_bytes = ar_json.encode("utf-8")
        _write_to_zip(zf, f"{prefix}/oscal/assessment-results.json", ar_bytes, manifest_files, "OSCAL AR")

        # 3. Generated documents
        docs = CRAGeneratedDocument.objects.filter(assessment=assessment)
        for doc in docs:
            zip_path = _DOC_PATH_MAP.get(doc.document_kind)
            if not zip_path:
                continue
            content = _get_generated_doc_content(doc, s3_client=docs_s3)
            if content:
                cra_ref = _DOC_CRA_REF.get(doc.document_kind, "")
                _write_to_zip(zf, f"{prefix}/{zip_path}", content, manifest_files, cra_ref)

        # 4. SBOMs from product components — fetch only the latest SBOM per component
        from django.db.models import OuterRef, Subquery

        latest_sbom_subquery = SBOM.objects.filter(component=OuterRef("pk")).order_by("-created_at").values("pk")[:1]
        components = list(
            Component.objects.filter(projects__products=product)
            .distinct()
            .annotate(latest_sbom_id=Subquery(latest_sbom_subquery))
        )
        sbom_ids = [c.latest_sbom_id for c in components if c.latest_sbom_id]
        sboms_by_id = {s.pk: s for s in SBOM.objects.filter(pk__in=sbom_ids)} if sbom_ids else {}

        for component in components:
            latest_sbom = sboms_by_id.get(component.latest_sbom_id) if component.latest_sbom_id else None
            if not latest_sbom:
                continue
            sbom_content = _get_sbom_content(latest_sbom, s3_client=sboms_s3)
            if sbom_content:
                ext = _FORMAT_EXT_MAP.get(latest_sbom.format, "json")
                sbom_path = f"{prefix}/sboms/{slugify(component.name)}-{component.id}.{ext}"
                _write_to_zip(zf, sbom_path, sbom_content, manifest_files, "Annex VII, §2")

        # 5. Harmonised-standards reference copy — so the bundle is
        # self-contained and auditors / notified bodies don't have to
        # chase the source JSON inside the sbomify codebase. The helper
        # returns ``None`` (already logged) on missing / unreadable
        # file; we simply skip the embedded copy in that case — the
        # rest of the export continues.
        standards_bytes = read_harmonised_standards_bytes()
        if standards_bytes is not None:
            _write_to_zip(
                zf,
                f"{prefix}/metadata/harmonised-standards.json",
                standards_bytes,
                manifest_files,
                "CRA standards reference",
            )

        # 6. Article 14 reporting README — documents the 2026-09-11
        # reporting deadline, the ENISA Single Reporting Platform, and
        # which template to use for each deadline.
        _write_to_zip(
            zf,
            f"{prefix}/article-14/README_REPORTING.md",
            _article_14_reporting_readme().encode("utf-8"),
            manifest_files,
            "Article 14 / Article 16",
        )

        # 7. Manifest — built after all other files are written so manifest_files
        # is complete. The manifest itself is NOT included in its own files list.
        manufacturer = get_manufacturer(assessment.team)
        manufacturer_name = manufacturer.name if manufacturer else ""
        manufacturer_name_is_placeholder = _is_placeholder_manufacturer(manufacturer_name)

        manifest = {
            "format_version": _MANIFEST_FORMAT_VERSION,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "product": {
                "id": product.id,
                "name": product.name,
            },
            "manufacturer": {
                "name": manufacturer_name,
                "address": manufacturer.address if manufacturer else "",
                "is_placeholder": manufacturer_name_is_placeholder,
            },
            "assessment_id": assessment.id,
            "cra_regulation": "EU 2024/2847",
            "product_category": assessment.product_category,
            "conformity_procedure": assessment.conformity_assessment_procedure,
            "integrity": {
                "hash_algorithm": "sha256",
                "manifest_hash_file": "metadata/manifest.sha256",
                "verification_doc": "metadata/INTEGRITY.md",
            },
            "files": manifest_files,
        }
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_path = f"{prefix}/metadata/manifest.json"
        zf.writestr(manifest_path, manifest_bytes)

        # 8. Self-hash of the manifest so a consumer can verify the
        # manifest hasn't been altered before trusting its per-file
        # hashes. We don't ship a cryptographic signature (operators
        # that need one apply cosign / PGP over the whole ZIP downstream),
        # but a self-hash is the minimum useful integrity signal.
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        # The checksum file declares the manifest path as
        # ``metadata/manifest.json`` (relative to the bundle root, not
        # the checksum file's own directory) because ``sha256sum -c``
        # resolves each entry against the working directory. INTEGRITY.md
        # tells operators to run the verification from the bundle root,
        # so the path here must match that working directory.
        zf.writestr(
            f"{prefix}/metadata/manifest.sha256",
            f"{manifest_sha256}  metadata/manifest.json\n".encode("utf-8"),
        )

        # 9. INTEGRITY.md — human-readable verification guide.
        # Branch on the team's configured signing state so the README
        # describes the signature the bundle actually carries (issue
        # #906). If signing is enabled but the signer later fails at
        # runtime, the README optimistically describes a signature
        # that isn't there — that's a known failure mode that surfaces
        # as "README references .sig but no .sig exists"; operators
        # see the signer's warning log and can re-export.
        try:
            _settings = assessment.team.compliance_settings
            _will_sign = bool(_settings.signing_enabled and _settings.signing_provider != "none")
            _sig_provider = _settings.signing_provider if _will_sign else None
        except Exception:
            _will_sign = False
            _sig_provider = None
        zf.writestr(
            f"{prefix}/metadata/INTEGRITY.md",
            _integrity_readme(manifest_sha256, signed=_will_sign, provider=_sig_provider).encode("utf-8"),
        )

    # Read entire ZIP into memory for hashing and upload. This is acceptable because
    # CRA export packages are typically <1MB (documents + SBOMs). The SpooledTemporaryFile
    # already spills to disk above 10MB, and we need the full bytes for SHA-256 hashing
    # and the subsequent S3 upload anyway — streaming would require two passes.
    buf.seek(0)
    zip_bytes = buf.read()
    buf.close()
    content_hash = hashlib.sha256(zip_bytes).hexdigest()
    storage_key = f"compliance/exports/{assessment.id}/{content_hash}.zip"

    # Upload to S3 (reuse the docs_s3 client)
    try:
        docs_s3.upload_data_as_file(django_settings.AWS_DOCUMENTS_STORAGE_BUCKET_NAME, storage_key, zip_bytes)
    except Exception:
        logger.exception("Failed to upload export package to S3")
        return ServiceResult.failure("Failed to upload export package to storage", status_code=502)

    # Optional cosign / sigstore signing (issue #906). The signer
    # returns ``None`` when the team hasn't enabled signing or when
    # the configured provider couldn't produce a signature right now
    # (missing dep, missing OIDC token, runtime failure) — in every
    # case the export still ships unsigned so signing is a layered
    # enhancement, not a gate. Signature is stored at
    # ``<storage_key>.sig`` so it can be fetched via a parallel
    # presigned URL on download.
    from sbomify.apps.compliance.services._bundle_signer import sign_bundle

    signature_bytes = sign_bundle(zip_bytes, assessment.team)
    signature_storage_key: str | None = None
    if signature_bytes is not None:
        signature_storage_key = f"{storage_key}.sig"
        try:
            docs_s3.upload_data_as_file(
                django_settings.AWS_DOCUMENTS_STORAGE_BUCKET_NAME,
                signature_storage_key,
                signature_bytes,
            )
            # Surface the signature in the manifest so downstream
            # consumers can detect it without calling the API.
            integrity_block = manifest["integrity"]
            assert isinstance(integrity_block, dict)
            integrity_block["signature"] = {
                "present": True,
                "file": "metadata/bundle.sig",
                "provider": assessment.team.compliance_settings.signing_provider,
            }
        except Exception:
            # Signing failures never fail the export; log and drop the
            # side-car so the download endpoint doesn't advertise a
            # URL that will 404.
            logger.exception("Failed to upload signature side-car for export %s", storage_key)
            signature_storage_key = None

    package = CRAExportPackage.objects.create(
        assessment=assessment,
        storage_key=storage_key,
        content_hash=content_hash,
        manifest=manifest,
        created_by=user,
    )

    return ServiceResult.success(package)


def _write_to_zip(
    zf: zipfile.ZipFile,
    path: str,
    data: bytes,
    manifest_files: list[dict[str, str]],
    cra_reference: str,
) -> None:
    """Write data to ZIP and record in manifest."""
    zf.writestr(path, data)
    manifest_files.append(
        {
            "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "cra_reference": cra_reference,
        }
    )


# CRA export bundle URLs expire in 15 minutes rather than the boto3
# default of 1 h. These URLs point at regulated evidence (Annex VII
# technical documentation); keeping the unauthenticated window tight
# reduces the blast radius of a leaked URL in a referer header,
# copy-pasted ticket, or mis-routed chat message. 900 s is still
# long enough for a human to click "Download" on the wizard.
_PRESIGNED_URL_EXPIRY_SECONDS = 900


def get_download_url(package: CRAExportPackage) -> ServiceResult[str]:
    """Generate a presigned S3 URL for the CRA bundle ZIP.

    Returns a short-lived URL (see ``_PRESIGNED_URL_EXPIRY_SECONDS``)
    with a forced ``Content-Disposition: attachment`` header so the
    browser downloads the bundle instead of rendering the ZIP inline
    (which some viewers attempt for JSON-looking responses). The
    filename is set to a deterministic slug derived from the product
    name + short hash so auditors can tell bundles apart on disk.
    """
    try:
        import boto3

        s3_client = boto3.client(
            "s3",
            region_name=django_settings.AWS_REGION,
            endpoint_url=django_settings.AWS_ENDPOINT_URL_S3,
            aws_access_key_id=django_settings.AWS_DOCUMENTS_ACCESS_KEY_ID,
            aws_secret_access_key=django_settings.AWS_DOCUMENTS_SECRET_ACCESS_KEY,
        )
        product_slug = slugify(package.assessment.product.name) or package.assessment.product.id
        filename = f"cra-package-{product_slug}-{package.content_hash[:12]}.zip"
        url: str = s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": django_settings.AWS_DOCUMENTS_STORAGE_BUCKET_NAME,
                "Key": package.storage_key,
                "ResponseContentDisposition": f'attachment; filename="{filename}"',
                "ResponseContentType": "application/zip",
            },
            ExpiresIn=_PRESIGNED_URL_EXPIRY_SECONDS,
        )
        return ServiceResult.success(url)
    except Exception:
        logger.exception("Failed to generate presigned URL")
        return ServiceResult.failure("Failed to generate download URL", status_code=500)


def get_signature_download_url(package: CRAExportPackage) -> ServiceResult[str | None]:
    """Generate a presigned URL for the side-car signature, if present.

    Returns ``ServiceResult.success(None)`` when the package wasn't
    signed at export time (issue #906). Returns a presigned URL to
    ``<storage_key>.sig`` when the manifest's integrity block records
    a signature — the client renders it as a second "Download
    signature" button next to the bundle.

    The signature file inherits the same short TTL as the bundle
    itself; both belong to the same unauthenticated release window.
    """
    integrity = (package.manifest or {}).get("integrity", {})
    signature = integrity.get("signature") if isinstance(integrity, dict) else None
    if not isinstance(signature, dict) or not signature.get("present"):
        return ServiceResult.success(None)

    try:
        import boto3

        s3_client = boto3.client(
            "s3",
            region_name=django_settings.AWS_REGION,
            endpoint_url=django_settings.AWS_ENDPOINT_URL_S3,
            aws_access_key_id=django_settings.AWS_DOCUMENTS_ACCESS_KEY_ID,
            aws_secret_access_key=django_settings.AWS_DOCUMENTS_SECRET_ACCESS_KEY,
        )
        product_slug = slugify(package.assessment.product.name) or package.assessment.product.id
        filename = f"cra-package-{product_slug}-{package.content_hash[:12]}.zip.sig"
        url: str = s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": django_settings.AWS_DOCUMENTS_STORAGE_BUCKET_NAME,
                "Key": f"{package.storage_key}.sig",
                "ResponseContentDisposition": f'attachment; filename="{filename}"',
                "ResponseContentType": "application/json",
            },
            ExpiresIn=_PRESIGNED_URL_EXPIRY_SECONDS,
        )
        return ServiceResult.success(url)
    except Exception:
        logger.exception("Failed to generate signature presigned URL")
        return ServiceResult.failure("Failed to generate signature download URL", status_code=500)
