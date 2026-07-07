from __future__ import annotations

from django.db.models import Count, Prefetch, Q, QuerySet

from sbomify.apps.core.models import Component, Product
from sbomify.apps.sboms.models import SBOM, ProductIdentifier, ProductLink


def optimize_product_queryset(queryset: QuerySet[Product]) -> QuerySet[Product]:
    component_qs = Component.objects.only(
        "id", "name", "visibility", "is_global", "component_type", "team_id"
    ).order_by("name")
    identifier_qs = ProductIdentifier.objects.only(
        "id", "identifier_type", "value", "created_at", "product_id"
    ).order_by("identifier_type", "value")
    link_qs = ProductLink.objects.only(
        "id", "link_type", "title", "url", "description", "created_at", "product_id"
    ).order_by("link_type", "title")

    return (
        queryset.select_related("team")
        .prefetch_related(
            Prefetch("components", queryset=component_qs),
            Prefetch("identifiers", queryset=identifier_qs),
            Prefetch("links", queryset=link_qs),
        )
        .annotate(component_count=Count("components", distinct=True))
        # Stable order so paginated callers (e.g. list_products) don't drop or
        # duplicate rows across pages when the underlying table order changes.
        .order_by("name", "id")
    )


def optimize_component_queryset(queryset: QuerySet[Component]) -> QuerySet[Component]:
    return queryset.select_related("team").annotate(
        # Count only real SBOMs — CBOM/VEX rows live in the same table and must not inflate the badge.
        sbom_count=Count("sbom", filter=Q(sbom__bom_type=SBOM.BomType.SBOM), distinct=True),
        document_count=Count("document", distinct=True),
    )
