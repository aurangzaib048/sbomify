"""Record the VEX lifecycle screencast — the Trust Center before and after VEX.

Drives the customer-facing payoff of VEX on a release's public Trust Center page:

1. **Before.** The Vulnerability Posture card shows the raw scan result — one
   critical, one high, one medium — with no suppressions and no VEX to download.
2. **Apply the VEX.** A VEX is published for the release marking the critical
   ``not_affected`` (the vulnerable code path is never reached).
3. **After.** Reload. The critical drops out of the counts, the suppression note
   appears ("1 finding suppressed by VEX"), the critical is listed dimmed with
   its justification, and the release now offers a one-click VEX download.

The in-app VEX *upload* is its own screencast (``vex_upload.py``); this one is
the consumer side. Publishing a VEX normally enqueues an async job that
re-annotates the component's stored scan results (writing ``analysis_state`` onto
suppressed findings) and the merged release VEX is assembled on read. The
screencast compose stack runs neither the scanner nor the worker, so ``_apply_vex``
writes the exact end state that re-annotation would — one ``analysis_state`` write
plus the VEX artifact on the release — between the "before" and "after" loads.
"""

import pytest
from django.urls import reverse
from playwright.sync_api import Page

from conftest import pace
from sbomify.apps.core.models import Release, ReleaseArtifact
from sbomify.apps.plugins.models import AssessmentRun
from sbomify.apps.sboms.models import SBOM, Component, Product
from sbomify.apps.teams.models import Team

COMPONENT_NAME = "Compression Core Library"
PRODUCT_NAME = "Pied Piper Compression Engine"
SBOM_NAME = "com.piedpiper/compression-core"

# The critical the VEX suppresses.
SUPPRESSED_CVE = "CVE-2024-12345"

# Raw scan findings for the release's SBOM before any VEX is applied: one
# critical, one high, one medium, none suppressed. Shapes mirror what a security
# scanner stores on an AssessmentRun.
RAW_FINDINGS = [
    {
        "id": SUPPRESSED_CVE,
        "severity": "critical",
        "title": "Server-side request forgery in requests",
        "component": {"name": "requests", "version": "2.32.3", "purl": "pkg:pypi/requests@2.32.3"},
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


@pytest.fixture
def vex_release(deletable_team: Team) -> dict:
    """Seed a public release whose SBOM has an unmitigated critical.

    A completed security run carries the raw findings with no ``analysis_state``
    yet, so the "before" Trust Center shows the full risk. No VEX is attached to
    the release yet — ``_apply_vex`` adds it.
    """
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
            "summary": {"by_severity": {"critical": 1, "high": 1, "medium": 1}, "total_findings": 3},
        },
    )

    return {"component": component, "sbom": sbom, "product": product, "release": release, "run": run}


def _apply_vex(component: Component, release: Release, run: AssessmentRun) -> None:
    """Apply what publishing a VEX + async re-annotation would do live.

    The worker writes ``analysis_state``/``analysis_justification`` onto the
    suppressed finding in the stored scan result, and the release's merged VEX is
    assembled from the newest VEX of each component on read. We reproduce both:
    mark the critical suppressed, and attach a VEX artifact to the release.
    """
    for finding in run.result["findings"]:
        if finding["id"] == SUPPRESSED_CVE:
            finding["analysis_state"] = "not_affected"
            finding["analysis_justification"] = "code_not_reachable"
    run.save(update_fields=["result"])

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
    ReleaseArtifact.objects.create(release=release, sbom=vex)


@pytest.mark.django_db(transaction=True)
def vex_lifecycle(recording_page: Page, vex_release: dict) -> None:
    page = recording_page

    release = vex_release["release"]
    product = vex_release["product"]
    public_url = reverse(
        "core:release_details_public",
        kwargs={"product_id": product.id, "release_id": release.id},
    )

    posture_heading = page.locator("h4:has-text('Vulnerability Posture')")

    # ── 1. Before — the raw posture on the Trust Center ──────────────────
    page.goto(public_url)
    page.wait_for_load_state("networkidle")

    posture_heading.wait_for(state="visible", timeout=15_000)
    posture_heading.scroll_into_view_if_needed()
    # Hold on the raw breakdown (critical 1, high 1, medium 1, no suppressions).
    pace(page, 4000)

    # ── 2. Publish the VEX (see _apply_vex) ──────────────────────────────
    _apply_vex(vex_release["component"], release, vex_release["run"])

    # ── 3. After — the VEX-applied posture + download ────────────────────
    page.goto(public_url)
    page.wait_for_load_state("networkidle")

    posture_heading.wait_for(state="visible", timeout=15_000)
    posture_heading.scroll_into_view_if_needed()
    pace(page, 2000)

    # The suppression note only renders once suppressed_count > 0.
    suppression_note = page.locator("text=suppressed by VEX").first
    suppression_note.wait_for(state="visible", timeout=10_000)
    suppression_note.scroll_into_view_if_needed()
    pace(page, 2500)

    # The suppressed critical is listed dimmed with its VEX justification.
    suppressed_cve = page.locator(f"span:text-is('{SUPPRESSED_CVE}')").first
    suppressed_cve.wait_for(state="visible", timeout=10_000)
    suppressed_cve.scroll_into_view_if_needed()
    pace(page, 3000)

    # The release now offers a one-click VEX download.
    vex_download = page.locator("a[title='Download latest VEX (CycloneDX)']").first
    vex_download.wait_for(state="visible", timeout=10_000)
    vex_download.scroll_into_view_if_needed()
    pace(page, 1200)
    vex_download.hover()
    pace(page, 3000)
