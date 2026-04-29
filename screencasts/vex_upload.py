"""Record the VEX usage screencast.

Drives: Dashboard → Components → click into a component that already has
both an SBOM and a VEX artifact attached → show the BOMs table with the
SBOM and VEX badges side-by-side → highlight the VEX badge.

VEX uploads today flow through the artifact API (``POST
/api/v1/sboms/artifact/cyclonedx/<component_id>?bom_type=vex``) — the
in-app drag-drop uploader does not yet expose a VEX type selector. The
screencast therefore demonstrates the *visible end-state* (a VEX
artifact rendered next to its SBOM) rather than the upload itself; the
companion FAQ article (``how-do-i-use-vex``) covers the API and CI
upload paths in prose.
"""

import pytest
from playwright.sync_api import Page

from conftest import (
    click_into_row,
    hover_and_click,
    navigate_to_components,
    pace,
    start_on_dashboard,
)
from sbomify.apps.sboms.models import SBOM, Component
from sbomify.apps.teams.models import Team

COMPONENT_NAME = "Pied Piper Compression Core"


@pytest.fixture
def component_with_sbom_and_vex(deletable_team: Team) -> dict:
    """Seed a component that already has both a CycloneDX SBOM and a VEX.

    Returns a dict with ``component``, ``sbom``, and ``vex`` keys so the
    test can assert against either if needed. Both records are created
    via the ORM directly — the screencast is recording the *display*
    side, not the upload pipeline.
    """
    component = Component.objects.create(team=deletable_team, name=COMPONENT_NAME)

    sbom = SBOM.objects.create(
        name="com.piedpiper/compression-core",
        version="2.1.0",
        format="cyclonedx",
        format_version="1.6",
        sbom_filename="compression-core-2.1.0.cdx.json",
        source="api",
        bom_type="sbom",
        component=component,
    )

    vex = SBOM.objects.create(
        name="com.piedpiper/compression-core",
        version="2.1.0",
        format="cyclonedx",
        format_version="1.6",
        sbom_filename="compression-core-2.1.0.vex.cdx.json",
        source="api",
        bom_type="vex",
        component=component,
    )

    return {"component": component, "sbom": sbom, "vex": vex}


@pytest.mark.django_db(transaction=True)
def vex_upload(recording_page: Page, component_with_sbom_and_vex: dict) -> None:
    page = recording_page

    start_on_dashboard(page)

    # ── 1. Navigate to Components ────────────────────────────────────────
    navigate_to_components(page)

    # ── 2. Click into the seeded component ───────────────────────────────
    click_into_row(page, COMPONENT_NAME)

    # ── 3. Scroll to the BOMs table so both artifacts are visible ────────
    # The table column "Type" renders the bom_type as a coloured badge —
    # SBOM is blue (tw-badge-info), VEX is amber (tw-badge-warning).
    bom_type_header = page.locator("text=TYPE").first
    bom_type_header.wait_for(state="visible", timeout=15_000)
    bom_type_header.scroll_into_view_if_needed()
    pace(page, 1500)

    # ── 4. Hover the VEX badge so the cursor draws attention to it ──────
    # The Alpine binding renders the badge text uppercased ("VEX").
    vex_badge = page.locator("span.tw-badge-warning:text-is('VEX')").first
    vex_badge.wait_for(state="visible", timeout=10_000)
    vex_badge.scroll_into_view_if_needed()
    pace(page, 600)
    vex_badge.hover()
    pace(page, 1500)

    # ── 5. Hover the SBOM badge to show they coexist on the same component
    sbom_badge = page.locator("span.tw-badge-info:text-is('SBOM')").first
    sbom_badge.wait_for(state="visible", timeout=10_000)
    sbom_badge.scroll_into_view_if_needed()
    pace(page, 400)
    sbom_badge.hover()
    pace(page, 1500)

    # ── 6. Click into the VEX row to land on its detail page ─────────────
    # The row name column links into the SBOM/VEX detail view; the same
    # template handles either type (bom_type drives the page header).
    vex_row_link = page.locator("tr", has=vex_badge).locator("a").first
    vex_row_link.wait_for(state="visible", timeout=10_000)
    pace(page, 500)
    hover_and_click(page, vex_row_link)
    page.wait_for_load_state("networkidle")
    pace(page, 2500)
