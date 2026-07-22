from __future__ import annotations

from typing import Any

from sbomify.apps.core.models import Component, Release
from sbomify.apps.plugins.models import AssessmentRun
from sbomify.apps.sboms.models import SBOM

_SEVERITIES = ("critical", "high", "medium", "low")


def _row_status(vuln: dict[str, int] | None) -> str:
    """The single filterable status of a component row — its worst severity,
    ``clean`` for a scanned row with no findings, ``not_scanned`` otherwise."""
    if vuln is None:
        return "not_scanned"
    for severity in _SEVERITIES:
        if vuln[severity]:
            return severity
    return "clean"


def build_product_components_rows(product_id: str) -> dict[str, Any]:
    """The product page's components-and-security table plus its rollup badge.

    One row per assigned component with its latest SBOM version and the same
    merged-by-alias, VEX-aware severity counts the component page shows, so the
    numbers agree across pages. Batched: one query for components, one for the
    latest SBOM per component, one for each provider's latest run per SBOM.
    Rows sort worst-first.
    """
    from sbomify.apps.vulnerability_scanning.utils import extract_finding_rows, merge_findings_by_alias
    from sbomify.apps.vulnerability_scanning.vex import load_vex_suppressions

    components = list(Component.objects.filter(products__id=product_id).order_by("name").values("id", "name"))
    component_ids = [c["id"] for c in components]

    latest_sboms = (
        SBOM.objects.filter(component_id__in=component_ids, bom_type=SBOM.BomType.SBOM)
        .order_by("component_id", "-created_at")
        .distinct("component_id")
        .values("id", "component_id", "version")
    )
    sbom_by_component = {row["component_id"]: row for row in latest_sboms}
    sbom_ids = [row["id"] for row in latest_sboms]

    runs = (
        AssessmentRun.objects.filter(sbom_id__in=sbom_ids, category="security", status="completed")
        .order_by("sbom_id", "plugin_name", "-created_at")
        .distinct("sbom_id", "plugin_name")
        .values("sbom_id", "result", "created_at")
    )
    results_by_sbom: dict[str, list[dict[str, Any] | None]] = {}
    last_scan_by_sbom: dict[str, Any] = {}
    for run in runs:
        sbom_id = str(run["sbom_id"])
        results_by_sbom.setdefault(sbom_id, []).append(run["result"])
        if sbom_id not in last_scan_by_sbom or run["created_at"] > last_scan_by_sbom[sbom_id]:
            last_scan_by_sbom[sbom_id] = run["created_at"]

    rows: list[dict[str, Any]] = []
    rollup = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    vex_cache: dict[Any, list[dict[str, Any]]] = {}
    for component in components:
        sbom = sbom_by_component.get(component["id"])
        row: dict[str, Any] = {
            "id": component["id"],
            "name": component["name"],
            "version": sbom["version"] if sbom else "",
            "vuln": None,
            "last_scan": None,
        }
        if sbom:
            provider_results = results_by_sbom.get(str(sbom["id"]))
            if provider_results:
                statements = load_vex_suppressions(component["id"], cache=vex_cache)
                findings = extract_finding_rows(merge_findings_by_alias(provider_results), statements)
                counts = {"total": len(findings)}
                for severity in _SEVERITIES:
                    counts[severity] = sum(1 for f in findings if f["severity"] == severity)
                    rollup[severity] += counts[severity]
                rollup["total"] += counts["total"]
                row["vuln"] = counts
                row["last_scan"] = last_scan_by_sbom.get(str(sbom["id"]))
        row["status"] = _row_status(row["vuln"])
        rows.append(row)

    rows.sort(
        key=lambda r: (
            -(r["vuln"] or {}).get("critical", 0),
            -(r["vuln"] or {}).get("high", 0),
            -(r["vuln"] or {}).get("medium", 0),
            -(r["vuln"] or {}).get("low", 0),
            r["name"].lower(),
        )
    )
    return {"rows": rows, "rollup": rollup}


def build_product_releases_summary(product_id: str) -> dict[str, Any]:
    """The releases strip: the release that represents "now" plus the total count."""
    releases = Release.objects.filter(product_id=product_id)
    total = releases.count()
    latest = releases.filter(is_latest=True).first() or releases.first()
    summary: dict[str, Any] = {"total": total, "latest": None}
    if latest:
        summary["latest"] = {
            "id": latest.id,
            "name": latest.name,
            "version": latest.version,
            "is_latest": latest.is_latest,
            "is_prerelease": latest.is_prerelease,
            "date": latest.released_at or latest.created_at,
            "artifact_count": latest.artifacts.count(),
        }
    return summary
