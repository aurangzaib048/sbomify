"""ENISA Single Reporting Platform (SRP) client adapter.

CRA Art 14 mandates automated submission of Early Warning (24 h),
Vulnerability Notification (72 h) and Final Report (14 d) filings to
the ENISA SRP for actively-exploited vulnerabilities and severe
incidents. The obligation applies from 2026-09-11.

**State as of 2026-04:** the SRP is not yet operational. ENISA has
not published the REST endpoint, authentication scheme, or payload
schema. A testing window is planned in the months leading up to the
go-live date.

What this module provides today:

* ``SrpAdapter`` — the transport seam. A concrete implementation
  will drop in a single class next to :class:`NullSrpAdapter` when
  the spec is published; call sites don't change.
* ``NullSrpAdapter`` — the installed default. Every ``submit`` call
  raises :class:`SrpAdapterNotConfigured` which is caught by
  :func:`submit_report` and persisted as a ``CRAReportSubmission``
  row with ``status="adapter_not_configured"`` and the same audit
  event emitted for a real failure — so the audit trail reflects the
  attempt regardless of transport readiness.
* ``submit_report`` — the public service-layer entry point. Does
  idempotency, ``CRAReportSubmission`` row persistence, adapter
  dispatch, status + acknowledgement capture, and audit logging.
  Call sites (wizard / API / cron) always go through this.

See issue #904 for the tracking record and the anticipated
transition plan.
"""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from django.db import IntegrityError, transaction
from django.utils import timezone

from sbomify.apps.compliance.models import CRAReportSubmission
from sbomify.apps.core.services.results import ServiceResult

if TYPE_CHECKING:
    from sbomify.apps.compliance.models import CRAAssessment
    from sbomify.apps.core.models import User


_audit_logger = logging.getLogger("sbomify.compliance.audit")


class SrpAdapterNotConfigured(RuntimeError):
    """Raised by the default adapter when no SRP transport is wired.

    Caught inside :func:`submit_report` and persisted as a ``CRAReportSubmission``
    with ``status="adapter_not_configured"``; surfaces to API callers as
    501 so a client UI can distinguish "we tried, the upstream isn't
    available yet" from a generic 500.
    """


class SrpSubmissionRejected(RuntimeError):
    """Raised by a real adapter when the SRP returns a 4xx error envelope."""


class SrpAdapter(ABC):
    """Transport seam for ENISA SRP submissions.

    Concrete adapters return a ``dict`` acknowledgement on success,
    raise :class:`SrpSubmissionRejected` on a 4xx semantic rejection
    (captured on the submission row as a ``FAILED`` with the error
    payload), or raise any other exception to indicate a transient
    error that the caller may retry.
    """

    @abstractmethod
    def submit(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Submit a single Art 14 report. Return the SRP acknowledgement envelope."""


class NullSrpAdapter(SrpAdapter):
    """Default adapter used while the SRP is not yet operational."""

    def submit(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:  # noqa: ARG002
        raise SrpAdapterNotConfigured(
            "ENISA Single Reporting Platform transport is not yet available "
            "(CRA Art 14 go-live 2026-09-11). Tracked in issue #904."
        )


_adapter: SrpAdapter = NullSrpAdapter()


def set_adapter(adapter: SrpAdapter) -> None:
    """Replace the module-level adapter. Intended for tests and the future transport wire-up."""
    global _adapter
    _adapter = adapter


def get_adapter() -> SrpAdapter:
    return _adapter


def _canonical_payload(payload: dict[str, Any]) -> str:
    """Stable JSON representation for idempotency hashing.

    ``sort_keys`` + ``separators`` avoid whitespace / key-order churn
    flipping the idempotency key on repeat submissions of the same
    logical report.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def build_idempotency_key(assessment_id: str, kind: str, payload: dict[str, Any]) -> str:
    """Derive the idempotency key from the triple (assessment, kind, payload bytes).

    Any two operator attempts to submit the same logical report for
    the same assessment collapse onto one row; changing any byte of
    the payload produces a new row.
    """
    h = hashlib.sha256(_canonical_payload(payload).encode("utf-8")).hexdigest()
    return f"{assessment_id}:{kind}:{h}"


def submit_report(
    *,
    assessment: CRAAssessment,
    kind: str,
    payload: dict[str, Any],
    user: User,
) -> ServiceResult[CRAReportSubmission]:
    """Persist + dispatch an Art 14 SRP submission.

    Contract:

    * Always writes exactly one ``CRAReportSubmission`` row. A retry
      with byte-identical payload short-circuits to the existing row
      (idempotency).
    * On adapter-not-configured (today's NullSrpAdapter path) the row
      is marked ``ADAPTER_NOT_CONFIGURED`` and the result carries
      status 501 so the caller can distinguish "not yet implemented
      upstream" from a real 5xx.
    * On ``SrpSubmissionRejected`` the row is marked ``FAILED`` with
      the rejection envelope captured in ``error``.
    * On any other adapter exception the row is marked ``FAILED`` and
      the result carries 502 (classic transient upstream shape).
    * Emits ``cra.art14.submission`` audit events for every outcome
      so the trail reflects the attempt regardless of success.
    """
    idem_key = build_idempotency_key(str(assessment.pk), kind, payload)

    # Short-circuit idempotent retries without touching the adapter.
    # This uses the unique constraint on ``idempotency_key`` rather
    # than racy "check then create" — the DB remains the single
    # source of truth for identity.
    try:
        with transaction.atomic():
            submission = CRAReportSubmission.objects.create(
                assessment=assessment,
                kind=kind,
                idempotency_key=idem_key,
                payload=payload,
                submitted_by=user,
            )
    except IntegrityError:
        existing = CRAReportSubmission.objects.get(idempotency_key=idem_key)
        return ServiceResult.success(existing)

    adapter = get_adapter()
    try:
        acknowledgement = adapter.submit(kind, payload)
    except SrpAdapterNotConfigured as exc:
        submission.status = CRAReportSubmission.Status.ADAPTER_NOT_CONFIGURED
        submission.error = str(exc)
        submission.save(update_fields=["status", "error", "updated_at"])
        _audit_logger.info(
            "cra.art14.submission",
            extra={
                "event": "cra.art14.submission",
                "outcome": "adapter_not_configured",
                "user_id": getattr(user, "id", None),
                "assessment_id": str(assessment.pk),
                "submission_id": str(submission.pk),
                "kind": kind,
            },
        )
        return ServiceResult.failure(str(exc), status_code=501)
    except SrpSubmissionRejected as exc:
        submission.status = CRAReportSubmission.Status.FAILED
        submission.error = str(exc)
        submission.save(update_fields=["status", "error", "updated_at"])
        _audit_logger.info(
            "cra.art14.submission",
            extra={
                "event": "cra.art14.submission",
                "outcome": "rejected",
                "user_id": getattr(user, "id", None),
                "assessment_id": str(assessment.pk),
                "submission_id": str(submission.pk),
                "kind": kind,
            },
        )
        return ServiceResult.failure(str(exc), status_code=400)
    except Exception as exc:  # pragma: no cover — real transport not wired
        submission.status = CRAReportSubmission.Status.FAILED
        submission.error = f"transport error: {exc!r}"
        submission.save(update_fields=["status", "error", "updated_at"])
        _audit_logger.info(
            "cra.art14.submission",
            extra={
                "event": "cra.art14.submission",
                "outcome": "transport_error",
                "user_id": getattr(user, "id", None),
                "assessment_id": str(assessment.pk),
                "submission_id": str(submission.pk),
                "kind": kind,
            },
        )
        return ServiceResult.failure("SRP transport error", status_code=502)

    submission.status = CRAReportSubmission.Status.SUBMITTED
    submission.acknowledgement = acknowledgement
    submission.submitted_at = timezone.now()
    submission.save(update_fields=["status", "acknowledgement", "submitted_at", "updated_at"])
    _audit_logger.info(
        "cra.art14.submission",
        extra={
            "event": "cra.art14.submission",
            "outcome": "submitted",
            "user_id": getattr(user, "id", None),
            "assessment_id": str(assessment.pk),
            "submission_id": str(submission.pk),
            "kind": kind,
        },
    )
    return ServiceResult.success(submission)
