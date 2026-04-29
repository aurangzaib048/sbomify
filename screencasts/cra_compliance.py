"""Record the CRA Compliance Wizard screencast.

Drives: Dashboard → Products → click into Pied Piper → CRA Compliance
card → Continue Assessment → land on Step 1 of the wizard → walk the
visible sections → use the stepper to jump to Step 5 (Review & Export)
so the recording captures the full five-step shape.

The screencast pairs with the FAQ article at
``how-do-i-use-cra-compliance``. We pre-create a CRAAssessment via
ORM rather than driving the scope-screening checkboxes, because the
screening uses an Alpine x-model with a default that is reactive at
init time — clicking the visual label is racy on first paint and a
flaky gate would invalidate the whole recording. The FAQ enumerates
the screening questions in prose; the screencast shows the wizard
itself, which is the part users spend time in.
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
    )

    return {**pied_piper_with_sboms, "assessment": assessment}


@pytest.mark.django_db(transaction=True)
def cra_compliance(recording_page: Page, pied_piper_with_cra_assessment: dict) -> None:
    page = recording_page

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

    # ── 6. Show the stepper by scrolling back to the top ────────────────
    # The stepper renders all five steps with their numeric markers and
    # the "Step 1 of 5" badge — that is the FAQ's visual anchor.
    page.evaluate("window.scrollTo({ top: 0, behavior: 'smooth' })")
    pace(page, 2500)
