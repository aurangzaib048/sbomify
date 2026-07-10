"""Merge a release's CBOM (Cryptography BOM) artifacts into one document.

A release can pin a CBOM per component. Consumers of the Trust Center want a
single crypto BOM for the release, so this unions the cryptographic-asset
components (and their dependency edges) of the newest CBOM in each component's
release slot into one CycloneDX 1.6 document — the same shape as the merged VEX
download.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)


def _document_from_cbom_sbom(cbom: Any) -> dict[str, Any] | None:
    """Load a CBOM SBOM row's document from S3. ``None`` when absent or unreadable."""
    from botocore.exceptions import BotoCoreError, ClientError

    from sbomify.apps.core.object_store import S3Client

    if cbom is None or not cbom.sbom_filename:
        return None
    try:
        raw = S3Client("SBOMS").get_sbom_data(cbom.sbom_filename)
    except (ClientError, BotoCoreError) as exc:
        # A missing/unreadable object must not 500 the merge — skip this CBOM, but
        # log so a genuinely misconfigured/unreachable bucket stays diagnosable.
        logger.warning("Could not load CBOM artifact %s from S3: %s", cbom.sbom_filename, exc)
        return None
    if not raw:
        return None
    try:
        document = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return document if isinstance(document, dict) else None


def build_release_cbom(release: Any) -> dict[str, Any] | None:
    """Merge the CBOM pinned in each component's release slot into one CycloneDX document.

    Only CBOM artifacts actually in the release (newest per component) are merged, so a component
    added to the product later never bleeds into an old release. Returns ``None`` when the release
    holds no CBOM.
    """
    from django.utils import timezone

    from sbomify.apps.core.models import ReleaseArtifact
    from sbomify.apps.sboms.models import SBOM

    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    dep_by_ref: dict[str, dict[str, Any]] = {}  # merge dependsOn for a shared source ref
    seen_components: set[Any] = set()
    found = False
    artifacts = (
        ReleaseArtifact.objects.filter(release=release, sbom__bom_type=SBOM.BomType.CBOM)
        .select_related("sbom")
        .order_by("sbom__component_id", "-sbom__created_at")
    )
    for artifact in artifacts:
        cbom_sbom = artifact.sbom
        if cbom_sbom is None or cbom_sbom.component_id in seen_components:
            continue
        seen_components.add(cbom_sbom.component_id)
        document = _document_from_cbom_sbom(cbom_sbom)
        if document is None:
            continue
        found = True
        for comp in document.get("components") or []:
            if not isinstance(comp, dict):
                continue
            ref = comp.get("bom-ref")
            if ref and ref in seen_refs:
                continue
            if ref:
                seen_refs.add(ref)
            components.append(comp)
        for dep in document.get("dependencies") or []:
            if not isinstance(dep, dict):
                continue
            ref = dep.get("ref")
            if not isinstance(ref, str) or not ref:
                continue
            # A dependsOn entry is normatively a list of bom-ref strings; tolerate a
            # malformed CBOM by keeping only the string targets rather than raising
            # (a non-list dependsOn contributes nothing).
            raw_targets = dep.get("dependsOn")
            targets = [t for t in raw_targets if isinstance(t, str)] if isinstance(raw_targets, list) else []
            existing = dep_by_ref.get(ref)
            if existing is None:
                # Copy so merging into it never mutates the source document.
                new_dep = {**dep, "dependsOn": list(targets)}
                dep_by_ref[ref] = new_dep
                dependencies.append(new_dep)
            else:
                # Same source node in two CBOMs: union the targets rather than
                # dropping the second edge (which would hide crypto usage).
                have = set(existing["dependsOn"])
                for target in targets:
                    if target not in have:
                        have.add(target)
                        existing["dependsOn"].append(target)

    if not found:
        return None

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": timezone.now().isoformat(),
            "component": {
                "type": "application",
                "name": f"{release.product.name} {release.name}",
                "bom-ref": f"release-{release.id}",
            },
        },
        "components": components,
        "dependencies": dependencies,
    }
