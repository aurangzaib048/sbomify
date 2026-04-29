"""Record the CRA Compliance Wizard screencast.

Drives: Dashboard → Products → click into Pied Piper → CRA Compliance
card → Continue Assessment → land on Step 1 (Product Profile) → walk
the visible sections → navigate to Step 2 (SBOM Compliance) → navigate
to Step 5 (Review & Export) → highlight the Export Compliance Bundle
button.

The screencast pairs with the FAQ article at
``how-do-i-use-cra-compliance``. We pre-create the CRAScopeScreening,
OSCAL catalog/result and CRAAssessment via ORM rather than driving
the scope-screening checkboxes, because the screening uses an Alpine
x-model with a default that is reactive at init time — clicking the
visual label is racy on first paint and a flaky gate would invalidate
the whole recording.

To keep the stepper visually honest we update ``completed_steps`` and
``current_step`` on the assessment as the recording moves between
steps, then ``page.goto()`` directly. ``CRAStepView`` accepts any step
number, so we do not need to click stepper links (which only render
for steps already in ``completed_steps``); driving the database
mirrors what the user would see after pressing Save & Continue.
"""

import pytest
from playwright.sync_api import Page

from conftest import (
    PIED_PIPER_PRODUCT_NAME,
    hover_and_click,
    navigate_to_products,
    pace,
    start_on_dashboard,
)
from sbomify.apps.compliance.models import (
    CRAAssessment,
    CRAScopeScreening,
    OSCALAssessmentResult,
    OSCALCatalog,
)


@pytest.fixture
def pied_piper_with_cra_assessment(pied_piper_with_sboms: dict) -> dict:
    """Extend pied_piper_with_sboms with a CRAAssessment ready for the wizard.

    Pre-creates the scope screening (cra_applies=True), an OSCAL catalog
    and assessment result, and a CRAAssessment linked to the product so
    the wizard shell renders Step 1 immediately. Returns the same dict
    plus an 'assessment' key.
    """
    product = pied_piper_with_sboms["product"]
    team = product.team

    CRAScopeScreening.objects.create(
        product=product,
        team=team,
        has_data_connection=True,
        is_own_use_only=False,
        is_testing_version=False,
        is_covered_by_other_legislation=False,
        is_dual_use=False,
    )

    catalog = OSCALCatalog.objects.create(
        name="BSI TR-03183-1",
        version="1.0",
        catalog_json={"metadata": {"title": "BSI TR-03183-1 (screencast stub)"}},
    )
    oscal_result = OSCALAssessmentResult.objects.create(
        catalog=catalog,
        team=team,
        title="CRA OSCAL Result",
    )
    assessment = CRAAssessment.objects.create(
        team=team,
        product=product,
        oscal_assessment_result=oscal_result,
        # Fresh state — the recording advances completed_steps as it
        # moves through the wizard so the stepper shows the realistic
        # in-progress shape (current step blue, completed green, rest
        # muted) rather than implying everything is already done.
        completed_steps=[],
        current_step=1,
    )

    return {**pied_piper_with_sboms, "assessment": assessment}


def _suppress_error_toasts(page: Page) -> None:
    """Continuously dismiss any toast notifications during the recording.

    The product detail page lazy-loads several HTMX panels (Releases,
    Identifiers, Vulnerability Trends). In the screencast environment
    a few of those endpoints fail and pop "Failed to load …" toasts
    that have nothing to do with the wizard flow. We register a
    100 ms interval that drains the toast container so transient
    errors never make it into the recording.
    """
    page.add_init_script(
        """
        (() => {
            const drain = () => {
                const container = document.getElementById('toast-container');
                if (container) {
                    const data = window.Alpine?.$data(container);
                    if (data && Array.isArray(data.toasts)) data.toasts = [];
                }
                document.querySelectorAll('.tw-toast').forEach((el) => el.remove());
            };
            setInterval(drain, 100);
        })();
        """
    )


@pytest.mark.django_db(transaction=True)
def cra_compliance(recording_page: Page, pied_piper_with_cra_assessment: dict) -> None:
    page = recording_page

    _suppress_error_toasts(page)
    start_on_dashboard(page)

    # ── 1. Navigate to Products ──────────────────────────────────────────
    navigate_to_products(page)

    # ── 2. Click into Pied Piper ─────────────────────────────────────────
    product_link = page.locator(f"span.text-text:text-is('{PIED_PIPER_PRODUCT_NAME}')")
    product_link.wait_for(state="visible", timeout=15_000)
    pace(page, 500)
    hover_and_click(page, product_link)
    page.wait_for_load_state("networkidle")
    pace(page, 1500)

    # ── 3. Show the CRA Compliance card ──────────────────────────────────
    # The card sits mid-page among the product detail panels. With an
    # assessment present the CTA reads "Continue Assessment" — that is
    # the resume path most users will see day-to-day.
    continue_btn = page.locator("a:has-text('Continue Assessment')").first
    continue_btn.wait_for(state="visible", timeout=15_000)
    continue_btn.scroll_into_view_if_needed()
    pace(page, 2000)

    # ── 4. Open the wizard ──────────────────────────────────────────────
    hover_and_click(page, continue_btn)
    page.wait_for_load_state("networkidle")
    pace(page, 2000)

    # ── 5. Step 1: Product Profile ──────────────────────────────────────
    # Walk the visible sections so the recording captures the shape of
    # the first step. The wizard is sticky-headed; scrolling each h2
    # into view brings the next panel above the fold.
    product_info = page.locator("h2:has-text('Product Information')").first
    product_info.wait_for(state="visible", timeout=15_000)
    pace(page, 2500)

    classification = page.locator("h2:has-text('CRA Classification')").first
    classification.scroll_into_view_if_needed()
    pace(page, 2500)

    harmonised = page.locator("h2:has-text('Harmonised Standards Applicability')").first
    harmonised.scroll_into_view_if_needed()
    pace(page, 2500)

    # ── 6. Scroll back up so the stepper is fully visible ───────────────
    page.evaluate("window.scrollTo({ top: 0, behavior: 'smooth' })")
    pace(page, 2000)

    # ── 7. Advance to Step 2 (SBOM Compliance) ──────────────────────────
    # Mark Step 1 complete and advance current_step before navigating —
    # the stepper then renders Step 1 with a green check and Step 2 as
    # the active blue marker, matching what the user would see after
    # pressing Save & Continue from Step 1.
    assessment = pied_piper_with_cra_assessment["assessment"]
    assessment.completed_steps = [1]
    assessment.current_step = 2
    assessment.save(update_fields=["completed_steps", "current_step"])
    page.goto(f"/compliance/cra/{assessment.id}/step/2/")
    page.wait_for_load_state("networkidle")
    pace(page, 2000)

    # ── 8. Step 2: SBOM Compliance ──────────────────────────────────────
    # The first heading is "SBOM Compliance Summary" — the rolled-up
    # BSI TR-03183 status across the product. Below it the
    # "Components" panel lists each component with its individual
    # findings. Walking both gives viewers the per-product / per-
    # component shape the FAQ describes.
    sbom_summary = page.locator("h2:has-text('SBOM Compliance Summary')").first
    sbom_summary.wait_for(state="visible", timeout=15_000)
    pace(page, 2500)

    components_heading = page.locator("h2:has-text('Components')").first
    components_heading.scroll_into_view_if_needed()
    pace(page, 2500)

    # ── 9. Advance to Step 5 (Review & Export) ──────────────────────────
    # Mark Steps 1-4 complete to mirror a user who has worked through
    # the wizard. Skipping Steps 3 and 4 keeps the recording tight;
    # the FAQ enumerates them in prose. Step 5 is what the FAQ leads
    # with as the deliverable, so it is worth the extra screen time.
    page.evaluate("window.scrollTo({ top: 0, behavior: 'smooth' })")
    pace(page, 1500)

    assessment.completed_steps = [1, 2, 3, 4]
    assessment.current_step = 5
    assessment.save(update_fields=["completed_steps", "current_step"])
    page.goto(f"/compliance/cra/{assessment.id}/step/5/")
    page.wait_for_load_state("networkidle")
    pace(page, 2000)

    # ── 9. Highlight the Export Compliance Bundle button ────────────────
    # Hover (do not click) the export CTA — clicking would kick off a
    # real export that the screencast environment cannot complete (no
    # S3, no signing). The FAQ's "What is in the export bundle"
    # section unpacks what the button produces.
    summary_heading = page.locator("h2:has-text('Compliance Summary')").first
    summary_heading.wait_for(state="visible", timeout=15_000)
    pace(page, 2500)

    export_btn = page.locator("button:has-text('Export Compliance Bundle')").first
    export_btn.wait_for(state="visible", timeout=10_000)
    export_btn.scroll_into_view_if_needed()
    pace(page, 800)
    box = export_btn.bounding_box()
    if box:
        page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    pace(page, 2500)
