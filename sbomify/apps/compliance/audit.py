"""Audit logging for regulated CRA state changes.

CRA exports (Declaration of Conformity, technical documentation bundle)
are legally binding. Non-repudiation depends on a durable trail of who
changed what and when, particularly for:

- Scope-screening answers (they determine whether CRA applies at all).
- Step 1 classification (category, harmonised standard, support period).
- Finding status + justification changes on OSCAL controls.

Every mutation below logs a single INFO record. The log format is
intentionally structured (JSON-friendly ``extra`` dict) so a production
pipeline can ship it into an append-only audit store without having to
parse prose messages.

The logger name ``sbomify.compliance.audit`` is reserved for this
purpose; configure it in ``LOGGING`` to route audit events to a
dedicated sink that is excluded from log rotation / retention windows
that would truncate the trail.
"""

from __future__ import annotations

import logging
from typing import Any

from sbomify.apps.core.models import User

_LOG = logging.getLogger("sbomify.compliance.audit")


def _diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    """Return the subset of keys where the value changed.

    Kept tiny so audit records don't duplicate unchanged fields — the
    delta is what a regulator asks about, not the full row.
    """
    out: dict[str, tuple[Any, Any]] = {}
    for key, after_value in after.items():
        before_value = before.get(key)
        if before_value != after_value:
            out[key] = (before_value, after_value)
    return out


def log_scope_screening_change(
    *,
    user: User | None,
    product_id: str,
    team_id: int,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    """Record a CRAScopeScreening write. ``before`` is ``{}`` on create."""
    delta = _diff(before, after)
    if not delta:
        return
    _LOG.info(
        "cra.scope_screening.write",
        extra={
            "event": "cra.scope_screening.write",
            "user_id": getattr(user, "id", None),
            "team_id": team_id,
            "product_id": product_id,
            "delta": delta,
        },
    )


def log_step_save(
    *,
    user: User | None,
    assessment_id: str,
    team_id: int,
    step: int,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    """Record a wizard-step save. ``delta`` carries only changed fields."""
    delta = _diff(before, after)
    if not delta:
        return
    _LOG.info(
        "cra.assessment.step_save",
        extra={
            "event": "cra.assessment.step_save",
            "user_id": getattr(user, "id", None),
            "team_id": team_id,
            "assessment_id": assessment_id,
            "step": step,
            "delta": delta,
        },
    )


def log_finding_update(
    *,
    user: User | None,
    assessment_id: str,
    finding_id: str,
    control_id: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    """Record an OSCALFinding status/notes/justification change."""
    delta = _diff(before, after)
    if not delta:
        return
    _LOG.info(
        "cra.finding.update",
        extra={
            "event": "cra.finding.update",
            "user_id": getattr(user, "id", None),
            "assessment_id": assessment_id,
            "finding_id": finding_id,
            "control_id": control_id,
            "delta": delta,
        },
    )
