"""Billing and role checks for CRA Compliance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sbomify.apps.billing.config import is_billing_enabled
from sbomify.apps.billing.models import BillingPlan

if TYPE_CHECKING:
    from django.http import HttpRequest

    from sbomify.apps.compliance.models import CRAAssessment
    from sbomify.apps.core.models import Product
    from sbomify.apps.teams.models import Team


@dataclass(frozen=True)
class AccessCheckFailure:
    """Opaque access-check failure carrying the HTTP status to return.

    ``require_assessment_access`` / ``require_product_cra_access`` return
    this on denial. The view layer translates to ``HttpResponseForbidden``
    / ``HttpResponseNotFound``; the Ninja API layer translates to the
    equivalent ``(status_code, ErrorResponse(...))``. Centralising the
    decision in one place keeps the two surfaces from drifting on a
    future role or billing rule change.
    """

    status_code: int
    message: str


def check_cra_access(team: Team | None = None, *, billing_plan_key: str | None = None) -> bool:
    """Returns True if team has Business+ plan (or billing disabled).

    Pure key check — no DB query. Can be called with either a Team object
    or a billing_plan_key string from the session.
    """
    if not is_billing_enabled():
        return True
    raw_key = billing_plan_key or (team.billing_plan if team else None)
    if not raw_key:
        return False
    return raw_key.strip().lower() in BillingPlan.CRA_ELIGIBLE_PLAN_KEYS


def require_assessment_access(
    request: HttpRequest,
    assessment_id: str,
    *,
    allowed_roles: tuple[str, ...] = ("owner", "admin"),
) -> CRAAssessment | AccessCheckFailure:
    """Centralised access check for all CRAAssessment-bound endpoints.

    Returns the assessment on success; ``AccessCheckFailure`` otherwise.
    Both the web view and the Ninja API call this so any change to the
    role list, billing gate, or lookup semantics lands in one place.

    Returns 404 (via AccessCheckFailure) rather than 403 when the
    assessment belongs to a different team — closing a timing side-
    channel that lets an attacker enumerate assessment IDs across
    tenants.
    """
    from sbomify.apps.compliance.models import CRAAssessment
    from sbomify.apps.core.utils import verify_item_access

    try:
        assessment = CRAAssessment.objects.select_related("team", "product").get(pk=assessment_id)
    except CRAAssessment.DoesNotExist:
        return AccessCheckFailure(status_code=404, message="Not found")

    if not verify_item_access(request, assessment, list(allowed_roles)):
        # Collapse 403 into 404 so product-existence isn't leaked
        # through response-code differential.
        return AccessCheckFailure(status_code=404, message="Not found")

    if not check_cra_access(assessment.team):
        return AccessCheckFailure(status_code=403, message="CRA access requires a Business plan")

    return assessment


def require_product_cra_access(
    request: HttpRequest,
    product_id: str,
    *,
    allowed_roles: tuple[str, ...] = ("owner", "admin"),
) -> Product | AccessCheckFailure:
    """Centralised access check for Product-bound CRA endpoints.

    Same shape and intent as ``require_assessment_access``, returning
    the product on success. Used by scope-screening + start-assessment
    views, both of which previously inlined the same three-step check.
    """
    from sbomify.apps.core.models import Product
    from sbomify.apps.core.utils import verify_item_access

    try:
        product = Product.objects.select_related("team").get(pk=product_id)
    except Product.DoesNotExist:
        return AccessCheckFailure(status_code=404, message="Not found")

    if not verify_item_access(request, product, list(allowed_roles)):
        return AccessCheckFailure(status_code=404, message="Not found")

    if not check_cra_access(product.team):
        return AccessCheckFailure(status_code=403, message="CRA access requires a Business plan")

    return product
