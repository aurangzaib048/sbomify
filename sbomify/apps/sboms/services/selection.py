"""Picking one artifact per component, the same way everywhere."""

from __future__ import annotations

from django.db.models import QuerySet

from sbomify.apps.sboms.models import SBOM


def newest_by_component(queryset: QuerySet[SBOM]) -> dict[str, str]:
    """The newest artifact id per component in ``queryset``.

    Postgres ``DISTINCT ON`` keeps the first row of each ``component_id``
    group, so the ordering is the selection: ``component_id`` first because
    it is what is being made distinct, then newest-first inside the group.
    Callers filter to the artifacts they want; only the tie-break lives here,
    so two dashboards can never disagree about which artifact is current.
    """
    rows = queryset.order_by("component_id", "-created_at").distinct("component_id").values_list("component_id", "id")
    return dict(rows)
