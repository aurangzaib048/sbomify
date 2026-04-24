"""Tests for the ENISA SRP adapter seam (issue #904).

The transport is not yet published by ENISA — the default
``NullSrpAdapter`` always raises ``SrpAdapterNotConfigured``. These
tests lock the contract that when the transport IS wired up in
future, the surrounding service (idempotency, persistence, audit
logging) behaves correctly regardless of what the adapter returns.
"""

from __future__ import annotations

import pytest

from sbomify.apps.compliance.models import CRAReportSubmission, CRAScopeScreening
from sbomify.apps.compliance.services import srp_service
from sbomify.apps.compliance.services.srp_service import (
    NullSrpAdapter,
    SrpAdapter,
    SrpAdapterNotConfigured,
    SrpSubmissionRejected,
    build_idempotency_key,
    get_adapter,
    set_adapter,
    submit_report,
)
from sbomify.apps.compliance.services.wizard_service import get_or_create_assessment
from sbomify.apps.core.models import Product
from sbomify.apps.teams.models import ContactEntity, ContactProfile

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _disable_billing(settings):
    settings.BILLING = False


@pytest.fixture(autouse=True)
def _restore_default_adapter():
    """Snapshot + restore the module-level adapter so tests don't leak."""
    original = get_adapter()
    yield
    set_adapter(original)


@pytest.fixture
def product(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    return Product.objects.create(name="SRP Test Product", team=team)


@pytest.fixture
def manufacturer(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    profile, _ = ContactProfile.objects.get_or_create(team=team, name="Default", defaults={"is_default": True})
    ContactEntity.objects.get_or_create(
        profile=profile,
        name="SRP Manufacturer GmbH",
        defaults={"email": "legal@srp.example", "is_manufacturer": True},
    )


@pytest.fixture
def scope_screening(sample_team_with_owner_member, sample_user, product):
    return CRAScopeScreening.objects.create(
        product=product,
        team=sample_team_with_owner_member.team,
        has_data_connection=True,
        is_own_use_only=False,
        is_covered_by_other_legislation=False,
        created_by=sample_user,
    )


@pytest.fixture
def assessment(sample_team_with_owner_member, sample_user, product, scope_screening, manufacturer):
    result = get_or_create_assessment(product.id, sample_user, sample_team_with_owner_member.team)
    assert result.ok
    return result.value


# ---------------------------------------------------------------------------
# Idempotency-key derivation is pure and unit-testable without DB.
# ---------------------------------------------------------------------------


class TestIdempotencyKey:
    def test_identical_payloads_produce_same_key(self):
        k1 = build_idempotency_key("asm1", "early_warning", {"a": 1, "b": 2})
        k2 = build_idempotency_key("asm1", "early_warning", {"b": 2, "a": 1})
        assert k1 == k2, "key order must not change the idempotency key"

    def test_different_payloads_produce_different_keys(self):
        k1 = build_idempotency_key("asm1", "early_warning", {"a": 1})
        k2 = build_idempotency_key("asm1", "early_warning", {"a": 2})
        assert k1 != k2

    def test_kind_affects_key(self):
        k1 = build_idempotency_key("asm1", "early_warning", {"a": 1})
        k2 = build_idempotency_key("asm1", "final_report", {"a": 1})
        assert k1 != k2

    def test_assessment_id_affects_key(self):
        k1 = build_idempotency_key("asm1", "early_warning", {"a": 1})
        k2 = build_idempotency_key("asm2", "early_warning", {"a": 1})
        assert k1 != k2


# ---------------------------------------------------------------------------
# Default NullSrpAdapter contract.
# ---------------------------------------------------------------------------


class TestNullSrpAdapter:
    def test_submit_raises_not_configured(self):
        adapter = NullSrpAdapter()
        with pytest.raises(SrpAdapterNotConfigured):
            adapter.submit("early_warning", {"body": "anything"})

    def test_module_default_is_null_adapter(self):
        # Restore-default fixture guarantees this is the module state.
        assert isinstance(get_adapter(), NullSrpAdapter)


# ---------------------------------------------------------------------------
# submit_report behavioural contract.
# ---------------------------------------------------------------------------


class _FakeOkAdapter(SrpAdapter):
    def __init__(self, ack: dict) -> None:
        self.ack = ack
        self.calls: list[tuple[str, dict]] = []

    def submit(self, kind, payload):
        self.calls.append((kind, payload))
        return self.ack


class _FakeRejectAdapter(SrpAdapter):
    def submit(self, kind, payload):  # noqa: ARG002
        raise SrpSubmissionRejected("missing required field `cve_id`")


class _FakeTransientAdapter(SrpAdapter):
    def submit(self, kind, payload):  # noqa: ARG002
        raise RuntimeError("connection reset")


class TestSubmitReportAdapterNotConfigured:
    def test_persists_submission_as_adapter_not_configured(self, sample_user, assessment):
        result = submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.EARLY_WARNING,
            payload={"cve_id": "CVE-2026-00001"},
            user=sample_user,
        )
        assert not result.ok
        assert result.status_code == 501

        subs = list(CRAReportSubmission.objects.filter(assessment=assessment))
        assert len(subs) == 1
        assert subs[0].status == CRAReportSubmission.Status.ADAPTER_NOT_CONFIGURED
        assert "issue #904" in subs[0].error
        assert subs[0].acknowledgement is None
        assert subs[0].submitted_at is None

    def test_submission_captures_submitting_user(self, sample_user, assessment):
        submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.EARLY_WARNING,
            payload={"cve_id": "CVE-2026-00002"},
            user=sample_user,
        )
        submission = CRAReportSubmission.objects.get(assessment=assessment)
        assert submission.submitted_by_id == sample_user.id


class TestSubmitReportIdempotency:
    def test_second_call_with_identical_payload_returns_existing_row(self, sample_user, assessment):
        payload = {"cve_id": "CVE-2026-00003"}

        first = submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.EARLY_WARNING,
            payload=payload,
            user=sample_user,
        )
        second = submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.EARLY_WARNING,
            payload=payload,
            user=sample_user,
        )

        assert first.status_code == 501  # First raised not-configured.
        assert second.ok, "The idempotent short-circuit must surface as success"
        assert CRAReportSubmission.objects.filter(assessment=assessment).count() == 1
        assert second.value.pk == first_submission_pk(assessment)

    def test_different_payload_creates_new_row(self, sample_user, assessment):
        submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.EARLY_WARNING,
            payload={"cve_id": "CVE-2026-00004"},
            user=sample_user,
        )
        submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.EARLY_WARNING,
            payload={"cve_id": "CVE-2026-00005"},
            user=sample_user,
        )
        assert CRAReportSubmission.objects.filter(assessment=assessment).count() == 2


class TestSubmitReportWithWiredAdapter:
    def test_success_marks_submitted_and_captures_ack(self, sample_user, assessment):
        ack = {"srp_id": "abc123", "received_at": "2026-09-11T00:00:00Z"}
        set_adapter(_FakeOkAdapter(ack))

        result = submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.FINAL_REPORT,
            payload={"incident_id": "inc-1"},
            user=sample_user,
        )

        assert result.ok
        submission = CRAReportSubmission.objects.get(pk=result.value.pk)
        assert submission.status == CRAReportSubmission.Status.SUBMITTED
        assert submission.acknowledgement == ack
        assert submission.submitted_at is not None

    def test_rejection_marks_failed_and_returns_400(self, sample_user, assessment):
        set_adapter(_FakeRejectAdapter())

        result = submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.VULNERABILITY_NOTIFICATION,
            payload={"incomplete": True},
            user=sample_user,
        )

        assert not result.ok
        assert result.status_code == 400
        submission = CRAReportSubmission.objects.get(assessment=assessment)
        assert submission.status == CRAReportSubmission.Status.FAILED
        assert "missing required field" in submission.error

    def test_transport_error_marks_failed_and_returns_502(self, sample_user, assessment):
        set_adapter(_FakeTransientAdapter())

        result = submit_report(
            assessment=assessment,
            kind=CRAReportSubmission.Kind.EARLY_WARNING,
            payload={"cve_id": "CVE-2026-00006"},
            user=sample_user,
        )

        assert not result.ok
        assert result.status_code == 502
        submission = CRAReportSubmission.objects.get(assessment=assessment)
        assert submission.status == CRAReportSubmission.Status.FAILED
        assert "transport error" in submission.error


def first_submission_pk(assessment):
    return CRAReportSubmission.objects.get(assessment=assessment).pk
