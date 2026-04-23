"""PR #861 test-plan verification.

One focused pytest per line item in the PR #861 test plan. Each test
exercises the production code path that the Alpine wizard POSTs to and
asserts the promise the PR description makes about its behaviour. Delete
this file once the PR merges — it is bookkeeping for the reviewer, not a
long-lived regression asset.
"""

from __future__ import annotations

import datetime

import pytest
from django.db import connection
from django.test import Client
from django.urls import reverse

from sbomify.apps.compliance.models import (
    CRAAssessment,
    CRAScopeScreening,
    OSCALControl,
    OSCALFinding,
)
from sbomify.apps.compliance.services.oscal_service import (
    create_assessment_result,
    ensure_cra_catalog,
    update_finding,
)
from sbomify.apps.compliance.services.wizard_service import (
    get_or_create_assessment,
    save_step_data,
)
from sbomify.apps.core.models import Product
from sbomify.apps.core.tests.shared_fixtures import setup_authenticated_client_session
from sbomify.apps.teams.models import ContactEntity, ContactProfile


@pytest.fixture(autouse=True)
def _disable_billing(settings):
    """Mirror test_views.py — CRA views gate on billing plan, but the
    flow itself is what this module exercises."""
    settings.BILLING = False


@pytest.fixture
def web_client(sample_team_with_owner_member, sample_user):
    """Web client logged in as the team owner (mirrors test_views.py)."""
    client = Client()
    client.force_login(sample_user)
    setup_authenticated_client_session(client, sample_team_with_owner_member.team, sample_user)
    return client


@pytest.fixture
def _valid_manufacturer(sample_team_with_owner_member):
    """Mirror the pattern in test_wizard_service: step 1 refuses to
    mark complete without a real legal manufacturer on the team."""
    team = sample_team_with_owner_member.team
    profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
    ContactEntity.objects.create(
        profile=profile,
        name="Acme Labs GmbH",
        email="legal@acmelabs.example",
        is_manufacturer=True,
    )


@pytest.fixture
def product(sample_team_with_owner_member, _valid_manufacturer):
    """Product with enough metadata to let Step 1 pass the manufacturer gate."""
    team = sample_team_with_owner_member.team
    return Product.objects.create(name="Plan Verify Product", team=team)


@pytest.fixture
def scope_in_scope(product, sample_team_with_owner_member, sample_user):
    """In-scope screening so ``cra_start_assessment`` proceeds to step 1."""
    return CRAScopeScreening.objects.create(
        product=product,
        team=sample_team_with_owner_member.team,
        has_data_connection=True,
        created_by=sample_user,
    )


@pytest.fixture
def assessment(scope_in_scope, product, sample_user, sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    r = get_or_create_assessment(product.id, sample_user, team)
    assert r.ok and r.value is not None
    return r.value


@pytest.mark.django_db
class TestPr861TestPlan:
    # Item 2 — end-to-end wizard creation through all five steps
    def test_02_end_to_end_wizard(self, assessment, sample_user):
        OSCALFinding.objects.filter(
            assessment_result=assessment.oscal_assessment_result,
        ).update(status=OSCALFinding.FindingStatus.SATISFIED)

        steps = [
            (1, {
                "intended_use": "Home automation controller",
                "target_eu_markets": ["DE"],
                "product_category": "default",
                "harmonised_standard_applied": True,
                "support_period_end": f"{datetime.date.today().year + 6}-01-01",
                "manufacturer_name": "Acme Gmbh",
                "manufacturer_street_address": "Hauptstr. 1",
                "manufacturer_city": "Berlin",
                "manufacturer_postal_code": "10115",
                "manufacturer_country": "DE",
            }),
            (2, {}),
            (3, {}),
            (4, {}),
            (5, {}),
        ]
        for step, payload in steps:
            r = save_step_data(assessment, step, payload, sample_user)
            assert r.ok, f"step {step} failed: {r.error}"

        assessment.refresh_from_db()
        assert assessment.status == CRAAssessment.WizardStatus.COMPLETE
        assert assessment.completed_at is not None
        assert set(assessment.completed_steps) == {1, 2, 3, 4, 5}

    # Item 3 — Part II controls block N/A selection (backend 400)
    def test_03_part_ii_blocks_na(self, sample_team_with_owner_member, sample_user, product):
        catalog = ensure_cra_catalog()
        team = sample_team_with_owner_member.team
        ar = create_assessment_result(catalog, team, product, sample_user)
        part_ii = OSCALFinding.objects.filter(
            assessment_result=ar, control__is_mandatory=True
        ).first()
        assert part_ii is not None, "catalog must contain a Part II (mandatory) control"

        with pytest.raises(ValueError, match=r"(?i)mandatory|part ii"):
            update_finding(part_ii, "not-applicable", "", "with justification")

    # Item 4 — Part I N/A requires justification
    def test_04_part_i_requires_justification(self, sample_team_with_owner_member, sample_user, product):
        catalog = ensure_cra_catalog()
        team = sample_team_with_owner_member.team
        ar = create_assessment_result(catalog, team, product, sample_user)
        part_i = OSCALFinding.objects.filter(
            assessment_result=ar, control__is_mandatory=False
        ).first()
        assert part_i is not None

        with pytest.raises(ValueError):
            update_finding(part_i, "not-applicable", "", "")

        updated = update_finding(
            part_i, "not-applicable", "", "Incompatible with product design"
        )
        assert updated.status == "not-applicable"
        assert updated.justification == "Incompatible with product design"

    # Item 5 — scope screening gates wizard entry
    def test_05_scope_screening_gate(self, product, web_client):
        # No screening → 302 redirect to scope_screening
        resp = web_client.post(
            reverse("compliance:cra_start_assessment", kwargs={"product_id": product.id}),
        )
        assert resp.status_code in (301, 302)
        assert "/cra/scope/" in (resp.get("Location") or "")

        # Screening exists, out-of-scope → 400
        CRAScopeScreening.objects.create(
            product=product,
            team=product.team,
            has_data_connection=False,
            is_own_use_only=False,
            is_testing_version=False,
            is_covered_by_other_legislation=False,
            is_dual_use=False,
        )
        resp2 = web_client.post(
            reverse("compliance:cra_start_assessment", kwargs={"product_id": product.id}),
        )
        assert resp2.status_code == 400

        # Flip to in-scope → 302 to step 1
        CRAScopeScreening.objects.filter(product=product).update(has_data_connection=True)
        resp3 = web_client.post(
            reverse("compliance:cra_start_assessment", kwargs={"product_id": product.id}),
        )
        assert resp3.status_code in (301, 302)
        assert "/cra/" in (resp3.get("Location") or "")

    # Item 6 — conformity procedure options match category
    def test_06_class_ii_defaults_to_module_bc(self, assessment, sample_user):
        r = save_step_data(assessment, 1, {"product_category": "class_ii"}, sample_user)
        assert r.ok
        assert r.value.conformity_assessment_procedure == CRAAssessment.ConformityProcedure.MODULE_B_C

    def test_06_critical_defaults_to_module_bc_not_eucc(self, assessment, sample_user):
        r = save_step_data(assessment, 1, {"product_category": "critical"}, sample_user)
        assert r.ok
        assert r.value.conformity_assessment_procedure == CRAAssessment.ConformityProcedure.MODULE_B_C

    def test_06_invalid_procedure_for_category_rejected(self, assessment, sample_user):
        r = save_step_data(
            assessment,
            1,
            {"product_category": "default", "conformity_assessment_procedure": "eucc"},
            sample_user,
        )
        assert not r.ok and r.status_code == 400

    # Item 7 — support period <5y requires justification + 4k cap
    def test_07_support_period_short_without_justification_rejected(self, assessment, sample_user):
        short_date = f"{datetime.date.today().year + 2}-01-01"
        r = save_step_data(
            assessment,
            1,
            {"product_category": "default", "support_period_end": short_date},
            sample_user,
        )
        assert not r.ok and r.status_code == 400

    def test_07_support_period_short_with_justification_accepted(self, assessment, sample_user):
        short_date = f"{datetime.date.today().year + 2}-01-01"
        r = save_step_data(
            assessment,
            1,
            {
                "product_category": "default",
                "support_period_end": short_date,
                "support_period_short_justification": "Lifecycle ends by design at 2 years",
            },
            sample_user,
        )
        assert r.ok

    def test_07_support_period_justification_length_cap(self, assessment, sample_user):
        short_date = f"{datetime.date.today().year + 2}-01-01"
        r = save_step_data(
            assessment,
            1,
            {
                "product_category": "default",
                "support_period_end": short_date,
                "support_period_short_justification": "x" * 4_001,
            },
            sample_user,
        )
        assert not r.ok and r.status_code == 400 and "4000-character cap" in (r.error or "")

    # Item 8 — Class I + Module A requires harmonised standard confirmation
    def test_08_class_i_without_harmonised_standard_rejected(self, assessment, sample_user):
        r = save_step_data(assessment, 1, {"product_category": "class_i"}, sample_user)
        assert not r.ok
        assert r.status_code == 400
        assert "harmonised" in (r.error or "").lower()

    def test_08_class_i_with_harmonised_standard_accepted(self, assessment, sample_user):
        r = save_step_data(
            assessment,
            1,
            {
                "product_category": "class_i",
                "harmonised_standard_applied": True,
                "support_period_end": f"{datetime.date.today().year + 6}-01-01",
            },
            sample_user,
        )
        assert r.ok
        assert r.value.harmonised_standard_applied is True
        assert r.value.conformity_assessment_procedure == CRAAssessment.ConformityProcedure.MODULE_A

    # Item 9 — migration shape on the test database
    def test_09_migration_columns_and_backfill(self):
        with connection.cursor() as cur:
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = %s AND column_name IN %s",
                ["compliance_oscal_controls", ("is_mandatory", "annex_part")],
            )
            columns = {row[0] for row in cur.fetchall()}
        assert {"is_mandatory", "annex_part"}.issubset(columns)

        ensure_cra_catalog()
        assert OSCALControl.objects.filter(
            catalog__name="EU CRA Annex I",
            annex_part="part-ii",
            is_mandatory=True,
        ).exists()
        assert OSCALControl.objects.filter(
            catalog__name="EU CRA Annex I",
            annex_part="part-i",
            is_mandatory=False,
        ).exists()
