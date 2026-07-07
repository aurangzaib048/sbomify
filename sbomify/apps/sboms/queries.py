from __future__ import annotations

from typing import Optional

from sbomify.apps.sboms.models import SBOM


def get_latest_sbom_id_for_component(component_id: str) -> Optional[str]:
    # Only real SBOMs — a component's newest row may be a CBOM/VEX (same table), which must not
    # be treated as "the latest SBOM" (that would pin the vuln dashboard to an unscanned artifact).
    return (
        SBOM.objects.filter(component_id=component_id, bom_type=SBOM.BomType.SBOM)
        .order_by("-created_at")
        .values_list("id", flat=True)
        .first()
    )
