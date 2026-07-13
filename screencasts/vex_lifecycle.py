"""Record the VEX lifecycle screencast — generate → upload → suppress → publish.

Drives the full producer-to-consumer journey for a hand-authored CycloneDX VEX:

1. **The vulnerability.** Open the component. Its scan flagged a critical
   (``CVE-2024-12345`` in ``requests``) plus a high and a medium.
2. **Upload the VEX.** Expand the upload card and drop a CycloneDX VEX that marks
   the critical ``not_affected`` (the vulnerable code path is never reached). The
   VEX badge lands next to the SBOM in the BOMs table.
3. **Suppression.** The stored scan is re-annotated: the critical drops out of the
   component's severity counts.
4. **Publish.** The release's public Trust Center page shows the VEX-applied
   posture — the critical suppressed with its justification, and the VEX
   downloadable.

Three infrastructure notes:

1. **bom_type routing.** The in-app uploader POSTs to
   ``/api/v1/sboms/upload-file/<id>`` without a ``bom_type`` query parameter, so
   the endpoint defaults to ``sbom``. The endpoint accepts ``bom_type=vex`` for
   CycloneDX uploads; we wrap ``window.fetch`` via an init script so the existing
   UI records the VEX upload flow.
2. **S3 short-circuit.** The screencast compose stack runs no S3 service, so a
   real upload would fail at ``put_object``. We no-op ``upload_data_as_file`` for
   the recording so the upload-file endpoint succeeds and writes the VEX record.
3. **Re-annotation runs the real engine, fed directly.** In production, uploading
   a VEX enqueues a job that reads the VEX from S3 and re-annotates the stored
   scan. With no S3 the job cannot fetch the bytes, so ``_apply_vex`` runs the
   same engine functions (``derive_vex_suppressions`` + ``reapply_vex_to_stored_result``)
   on the in-memory VEX document. The suppression and rebuilt counts are the real
   engine's output — only the S3 round-trip is skipped.
"""

import json

import pytest
from django.urls import reverse
from playwright.sync_api import Locator, Page

from conftest import (
    click_into_row,
    hover_and_click,
    navigate_to_components,
    pace,
    start_on_dashboard,
)
from sbomify.apps.core.models import Release, ReleaseArtifact
from sbomify.apps.core.object_store import S3Client
from sbomify.apps.plugins.models import AssessmentRun
from sbomify.apps.sboms.models import SBOM, Component, Product
from sbomify.apps.teams.models import Team

COMPONENT_NAME = "Compression Core Library"
PRODUCT_NAME = "Pied Piper Compression Engine"
SBOM_NAME = "com.piedpiper/compression-core"

SUPPRESSED_CVE = "CVE-2024-12345"
SUPPRESSED_PURL = "pkg:pypi/requests@2.32.3"

# Raw scan findings for the release's SBOM before any VEX is applied: one
# critical, one high, one medium. Shapes mirror what a security scanner stores.
RAW_FINDINGS = [
    {
        "id": SUPPRESSED_CVE,
        "severity": "critical",
        "title": "Server-side request forgery in requests",
        "component": {"name": "requests", "version": "2.32.3", "purl": SUPPRESSED_PURL},
    },
    {
        "id": "CVE-2024-45210",
        "severity": "high",
        "title": "Improper certificate validation in urllib3",
        "component": {"name": "urllib3", "version": "2.0.7", "purl": "pkg:pypi/urllib3@2.0.7"},
    },
    {
        "id": "CVE-2024-33210",
        "severity": "medium",
        "title": "Prototype pollution in lodash",
        "component": {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
    },
]

# The hand-authored CycloneDX VEX. One statement marks the critical not_affected;
# the upload bytes and the suppression statements both derive from this document.
VEX_DOCUMENT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
    "version": 1,
    "metadata": {
        "timestamp": "2026-04-29T00:00:00Z",
        "component": {"type": "application", "name": SBOM_NAME, "version": "2.1.0"},
    },
    "vulnerabilities": [
        {
            "id": SUPPRESSED_CVE,
            "source": {"name": "NVD"},
            "ratings": [{"severity": "critical"}],
            "affects": [{"ref": SUPPRESSED_PURL}],
            "analysis": {
                "state": "not_affected",
                "justification": "code_not_reachable",
                "detail": (
                    "We use requests only for outbound HTTPS to a fixed allowlist "
                    "of internal hosts. The vulnerable redirect path is never exercised."
                ),
            },
        }
    ],
}
VEX_FILE_BYTES = json.dumps(VEX_DOCUMENT, indent=2).encode("utf-8")


@pytest.fixture
def vex_release(deletable_team: Team) -> dict:
    """Seed a public release whose scanned SBOM has an unmitigated critical."""
    component = Component.objects.create(team=deletable_team, name=COMPONENT_NAME)

    sbom = SBOM.objects.create(
        name=SBOM_NAME,
        version="2.1.0",
        format="cyclonedx",
        format_version="1.6",
        sbom_filename="compression-core-2.1.0.cdx.json",
        source="api",
        bom_type=SBOM.BomType.SBOM,
        component=component,
    )

    product = Product.objects.create(
        team=deletable_team,
        name=PRODUCT_NAME,
        description="Middle-out compression platform for enterprise data optimization",
        is_public=True,
    )
    product.components.set([component])

    release = Release.objects.create(product=product, name="v2.1.0", version="2.1.0")
    ReleaseArtifact.objects.create(release=release, sbom=sbom)

    run = AssessmentRun.objects.create(
        sbom=sbom,
        plugin_name="osv",
        plugin_version="1.0.0",
        plugin_config_hash="",
        category="security",
        run_reason="on_upload",
        status="completed",
        result={
            "findings": [dict(f) for f in RAW_FINDINGS],
            "summary": {
                "by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0},
                "total_findings": 3,
                "suppressed_count": 0,
            },
        },
    )

    return {"component": component, "sbom": sbom, "product": product, "release": release, "run": run}


def _patch_uploads_as_vex(page: Page) -> None:
    """Wrap window.fetch so upload-file requests carry bom_type=vex."""
    page.add_init_script(
        """
        (() => {
            const originalFetch = window.fetch.bind(window);
            window.fetch = function patchedFetch(input, init) {
                let url = typeof input === 'string' ? input : input.url;
                if (url && url.includes('/api/v1/sboms/upload-file/') && !url.includes('bom_type=')) {
                    const sep = url.includes('?') ? '&' : '?';
                    url = url + sep + 'bom_type=vex';
                    if (typeof input === 'string') {
                        input = url;
                    } else {
                        input = new Request(url, input);
                    }
                }
                return originalFetch(input, init);
            };
        })();
        """
    )


@pytest.fixture
def s3_short_circuit(monkeypatch: pytest.MonkeyPatch) -> None:
    """No-op the S3 put so the upload-file endpoint can succeed end-to-end."""
    monkeypatch.setattr(S3Client, "upload_data_as_file", lambda *args, **kwargs: None)


def _apply_vex(component: Component, release: Release, run: AssessmentRun) -> None:
    """Suppress via the real VEX engine, then attach the VEX to the release.

    Runs ``derive_vex_suppressions`` + ``reapply_vex_to_stored_result`` on the
    in-memory VEX document — the same functions the async job runs after reading
    the VEX from S3 — so the annotated findings and rebuilt severity counts are
    the engine's genuine output. Then attaches a VEX artifact so the release's
    merged VEX is downloadable on the Trust Center.
    """
    from sbomify.apps.vulnerability_scanning.vex import (
        derive_vex_suppressions,
        reapply_vex_to_stored_result,
    )

    statements = derive_vex_suppressions(VEX_DOCUMENT)
    run.result = reapply_vex_to_stored_result(run.result, statements)
    run.save(update_fields=["result"])

    vex = SBOM.objects.filter(component=component, bom_type=SBOM.BomType.VEX).order_by("-created_at").first()
    if vex is None:
        vex = SBOM.objects.create(
            name=SBOM_NAME,
            version="2.1.0",
            format="cyclonedx",
            format_version="1.6",
            sbom_filename="compression-core-2.1.0.vex.cdx.json",
            source="api",
            bom_type=SBOM.BomType.VEX,
            component=component,
        )
    ReleaseArtifact.objects.get_or_create(release=release, sbom=vex)


def _smooth_scroll(page: Page, locator: Locator, pause_ms: int = 1400) -> None:
    """Smoothly pan an element to the centre of the viewport, then pause.

    Instant ``scrollIntoView`` jumps read as jarring on the recording; a smooth
    animation plus a pause lets the pan land before the next action (and before
    any ``bounding_box`` read that follows).
    """
    locator.evaluate("el => el.scrollIntoView({ behavior: 'smooth', block: 'center' })")
    pace(page, pause_ms)


@pytest.mark.django_db(transaction=True)
def vex_lifecycle(recording_page: Page, vex_release: dict, s3_short_circuit: None) -> None:
    page = recording_page

    _patch_uploads_as_vex(page)

    component = vex_release["component"]
    release = vex_release["release"]
    product = vex_release["product"]
    component_url = reverse("core:component_details", kwargs={"component_id": component.id})
    public_url = reverse(
        "core:release_details_public",
        kwargs={"product_id": product.id, "release_id": release.id},
    )

    start_on_dashboard(page)

    # ── 1. The vulnerability — the component's scan flagged a critical ───
    navigate_to_components(page)
    click_into_row(page, COMPONENT_NAME)

    # The severity summary loads via HTMX (vulnerability trends). Hold on the
    # critical count card (the red count span, unique to the Critical card) so
    # viewers see the risk before the VEX is applied. Centre it in the viewport
    # so the fixed top nav doesn't cover it, and let the chart settle first.
    critical_card = page.locator("span.text-xl.font-bold.text-red-600").first
    critical_card.wait_for(state="visible", timeout=15_000)
    pace(page, 1500)
    _smooth_scroll(page, critical_card, 4000)

    # ── 2. Upload the hand-authored VEX ──────────────────────────────────
    upload_header = page.locator("#upload-sbom button").first
    upload_header.wait_for(state="visible", timeout=15_000)
    _smooth_scroll(page, upload_header, 1200)
    hover_and_click(page, upload_header)
    pace(page, 1200)

    helper_text = page.locator("#upload-sbom").locator("text=SBOM, VEX, CBOM").first
    helper_text.wait_for(state="visible", timeout=10_000)
    _smooth_scroll(page, helper_text, 2000)

    file_input = page.locator("#upload-sbom input[type='file']")
    with page.expect_response(
        lambda r: "/api/v1/sboms/upload-file/" in r.url and r.status == 201,
        timeout=15_000,
    ):
        file_input.set_input_files(
            files=[
                {
                    "name": "compression-core-2.1.0.vex.cdx.json",
                    "mimeType": "application/json",
                    "buffer": VEX_FILE_BYTES,
                }
            ]
        )

    # The uploader accepts the VEX (201). The component's BOMs table lists only
    # SBOM-type artifacts, so the VEX doesn't appear there — its effect shows as
    # the suppression below. Hold on the upload landing.
    pace(page, 2500)

    # ── 3. Suppression — re-annotate via the real engine (see _apply_vex) ─
    _apply_vex(component, release, vex_release["run"])

    page.goto(component_url)
    page.wait_for_load_state("networkidle")
    critical_card.wait_for(state="visible", timeout=15_000)
    pace(page, 1500)
    # The critical is gone from the counts now (0).
    _smooth_scroll(page, critical_card, 4000)

    # ── 4. Publish — the VEX-applied posture on the Trust Center ─────────
    page.goto(public_url)
    page.wait_for_load_state("networkidle")

    posture_heading = page.locator("h4:has-text('Vulnerability Posture')")
    posture_heading.wait_for(state="visible", timeout=15_000)
    _smooth_scroll(page, posture_heading, 2000)

    suppression_note = page.locator("text=suppressed by VEX").first
    suppression_note.wait_for(state="visible", timeout=10_000)
    _smooth_scroll(page, suppression_note, 2500)

    suppressed_cve = page.locator(f"span:text-is('{SUPPRESSED_CVE}')").first
    suppressed_cve.wait_for(state="visible", timeout=10_000)
    _smooth_scroll(page, suppressed_cve, 3000)

    vex_download = page.locator("a[title='Download latest VEX (CycloneDX)']").first
    vex_download.wait_for(state="visible", timeout=10_000)
    _smooth_scroll(page, vex_download, 1200)
    vex_download.hover()
    pace(page, 2500)
