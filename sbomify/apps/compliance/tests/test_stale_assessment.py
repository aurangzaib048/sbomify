"""Tests for the stale-assessment flow (issue #921).

When ``save_scope_screening`` flips ``CRAScopeScreening.cra_applies``
from ``True`` to ``False`` while a live assessment row exists, the
assessment transitions to ``CRAAssessment.WizardStatus.STALE``.
Mutation endpoints refuse edits with ``409`` until the operator
reconciles — either by flipping scope back on (auto-unstales) or by
deleting the assessment row entirely.
"""

from __future__ import annotations

import json

import pytest

from sbomify.apps.compliance.models import CRAAssessment, CRAScopeScreening
from sbomify.apps.compliance.services.wizard_service import (
    _status_from_completed_steps,
    get_or_create_assessment,
    save_scope_screening,
)
from sbomify.apps.core.models import Product
from sbomify.apps.core.tests.shared_fixtures import get_api_headers
from sbomify.apps.teams.models import ContactEntity, ContactProfile

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _disable_billing(settings):
    settings.BILLING = False


@pytest.fixture
def product(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    return Product.objects.create(name="Stale Flow Product", team=team)


@pytest.fixture
def manufacturer(sample_team_with_owner_member):
    """A non-placeholder manufacturer so ``get_or_create_assessment`` can proceed."""
    team = sample_team_with_owner_member.team
    profile, _ = ContactProfile.objects.get_or_create(team=team, name="Default", defaults={"is_default": True})
    ContactEntity.objects.get_or_create(
        profile=profile,
        name="Stale Manufacturer GmbH",
        defaults={"email": "legal@stale.example", "is_manufacturer": True},
    )


@pytest.fixture
def in_scope_screening(sample_team_with_owner_member, sample_user, product):
    return CRAScopeScreening.objects.create(
        product=product,
        team=sample_team_with_owner_member.team,
        has_data_connection=True,
        is_own_use_only=False,
        is_covered_by_other_legislation=False,
        created_by=sample_user,
    )


@pytest.fixture
def assessment(sample_team_with_owner_member, sample_user, product, in_scope_screening, manufacturer):
    result = get_or_create_assessment(product.id, sample_user, sample_team_with_owner_member.team)
    assert result.ok
    return result.value


class TestSaveScopeScreeningStaleTransitions:
    """Directly exercise the service-layer stale flag — no HTTP."""

    def test_flip_out_of_scope_marks_assessment_stale(self, sample_user, product, assessment):
        # Guard: the assessment starts non-stale.
        assert assessment.status != CRAAssessment.WizardStatus.STALE

        # Operator edits scope screening: product is own-use only → CRA no longer applies.
        result = save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": True, "is_covered_by_other_legislation": False},
        )
        assert result.ok

        assessment.refresh_from_db()
        assert assessment.status == CRAAssessment.WizardStatus.STALE

    def test_flip_back_in_scope_unstales_assessment(self, sample_user, product, assessment):
        # Stale the assessment first.
        save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": True, "is_covered_by_other_legislation": False},
        )
        assessment.refresh_from_db()
        assert assessment.status == CRAAssessment.WizardStatus.STALE

        # Operator re-scopes: CRA applies again.
        result = save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": False, "is_covered_by_other_legislation": False},
        )
        assert result.ok

        assessment.refresh_from_db()
        # Fresh assessment had no completed steps → DRAFT after unstaling.
        assert assessment.status == CRAAssessment.WizardStatus.DRAFT

    def test_flip_out_of_scope_is_noop_without_assessment(self, sample_user, product, in_scope_screening):
        """No assessment → nothing to flip; the save must not 500."""
        result = save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": True, "is_covered_by_other_legislation": False},
        )
        assert result.ok
        assert not CRAAssessment.objects.filter(product=product).exists()

    def test_same_scope_does_not_retrigger_stale(self, sample_user, product, assessment):
        """Re-saving with identical in-scope values must not flip status."""
        assessment.status = CRAAssessment.WizardStatus.IN_PROGRESS
        assessment.save(update_fields=["status"])

        result = save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": False, "is_covered_by_other_legislation": False},
        )
        assert result.ok

        assessment.refresh_from_db()
        assert assessment.status == CRAAssessment.WizardStatus.IN_PROGRESS

    def test_unstale_restores_status_from_completed_steps(self, sample_user, product, assessment):
        """Unstaling picks IN_PROGRESS when the operator had finished some steps."""
        assessment.completed_steps = [1, 2]
        assessment.status = CRAAssessment.WizardStatus.IN_PROGRESS
        assessment.save(update_fields=["completed_steps", "status"])

        save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": True, "is_covered_by_other_legislation": False},
        )
        assessment.refresh_from_db()
        assert assessment.status == CRAAssessment.WizardStatus.STALE

        save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": False, "is_covered_by_other_legislation": False},
        )
        assessment.refresh_from_db()
        assert assessment.status == CRAAssessment.WizardStatus.IN_PROGRESS

    def test_unstale_restores_complete_when_all_steps_done(self, sample_user, product, assessment):
        """Unstaling respects a fully completed wizard."""
        assessment.completed_steps = [1, 2, 3, 4, 5]
        assessment.save(update_fields=["completed_steps"])

        save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": True, "is_covered_by_other_legislation": False},
        )
        save_scope_screening(
            product=product,
            user=sample_user,
            data={"has_data_connection": True, "is_own_use_only": False, "is_covered_by_other_legislation": False},
        )
        assessment.refresh_from_db()
        assert assessment.status == CRAAssessment.WizardStatus.COMPLETE


class TestStatusFromCompletedSteps:
    """Unit tests for the helper that picks the unstale status."""

    def test_empty_completed_steps_is_draft(self):
        assert _status_from_completed_steps([]) == CRAAssessment.WizardStatus.DRAFT

    def test_partial_completed_steps_is_in_progress(self):
        assert _status_from_completed_steps([1, 2, 3]) == CRAAssessment.WizardStatus.IN_PROGRESS

    def test_all_five_steps_is_complete(self):
        assert _status_from_completed_steps([1, 2, 3, 4, 5]) == CRAAssessment.WizardStatus.COMPLETE

    def test_all_five_steps_out_of_order_is_complete(self):
        assert _status_from_completed_steps([5, 3, 2, 1, 4]) == CRAAssessment.WizardStatus.COMPLETE


class TestApiMutationGate:
    """Every mutation endpoint must short-circuit with 409 when the assessment is stale."""

    @pytest.fixture
    def stale_assessment(self, assessment):
        assessment.status = CRAAssessment.WizardStatus.STALE
        assessment.save(update_fields=["status"])
        return assessment

    def test_save_step_returns_409_on_stale(self, authenticated_api_client, stale_assessment):
        client, token = authenticated_api_client
        response = client.patch(
            f"/api/v1/compliance/cra/{stale_assessment.id}/step/1",
            data=json.dumps({"data": {}}),
            content_type="application/json",
            **get_api_headers(token),
        )
        assert response.status_code == 409
        body = response.json()
        assert body["error_code"] == "assessment_stale"

    def test_create_export_returns_409_on_stale(self, authenticated_api_client, stale_assessment):
        client, token = authenticated_api_client
        response = client.post(
            f"/api/v1/compliance/cra/{stale_assessment.id}/export",
            content_type="application/json",
            **get_api_headers(token),
        )
        assert response.status_code == 409
        assert response.json()["error_code"] == "assessment_stale"

    def test_read_endpoints_still_work_on_stale(self, authenticated_api_client, stale_assessment):
        """GET endpoints must continue to work so the operator can see the banner."""
        client, token = authenticated_api_client
        response = client.get(
            f"/api/v1/compliance/cra/{stale_assessment.id}/staleness",
            **get_api_headers(token),
        )
        # The staleness endpoint checks staleness of generated docs, not assessment status —
        # the only outcome we care about here is that the gate did not fire.
        assert response.status_code != 409

    def test_non_stale_mutations_still_succeed(self, authenticated_api_client, assessment):
        """Baseline: a non-stale assessment accepts step saves."""
        client, token = authenticated_api_client
        response = client.patch(
            f"/api/v1/compliance/cra/{assessment.id}/step/1",
            data=json.dumps({"data": {"intended_use": "Home automation"}}),
            content_type="application/json",
            **get_api_headers(token),
        )
        # 200 on success, NOT 409.
        assert response.status_code != 409
