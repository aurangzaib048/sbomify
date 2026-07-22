"""Workspace-level crypto readiness rollup.

Aggregates the persisted PQC AssessmentRun results (never the raw artifacts:
no S3 fan-out) across every component in a workspace: one row per component
keyed on its newest crypto-bearing artifact (newest CBOM, else newest SBOM),
with the latest completed pqc-readiness run's verdict, per-status counts,
vulnerable algorithm names, and the certificate expiry summary the plugin
stamps into run metadata.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sbomify.apps.core.models import Component
from sbomify.apps.plugins.models import AssessmentRun
from sbomify.apps.sboms.models import SBOM

PQC_PLUGIN = "pqc-readiness"

# Component verdicts, worst first. "no_crypto" = assessed, nothing to grade
# (skipped run); "not_assessed" = no artifact or no run yet.
_VERDICT_ORDER = {"at_risk": 0, "needs_review": 1, "ready": 2, "no_crypto": 3, "not_assessed": 4}


def _newest_by_component(component_ids: list[str], bom_type: str) -> dict[str, str]:
    rows = (
        SBOM.objects.filter(component_id__in=component_ids, bom_type=bom_type)
        .order_by("component_id", "-created_at")
        .distinct("component_id")
        .values_list("component_id", "id")
    )
    return {component_id: sbom_id for component_id, sbom_id in rows}


def build_workspace_crypto_rollup(team_id: int) -> dict[str, Any]:
    components = list(Component.objects.filter(team_id=team_id).order_by("name").values("id", "name"))
    component_ids = [c["id"] for c in components]
    newest_cbom = _newest_by_component(component_ids, SBOM.BomType.CBOM)
    newest_sbom = _newest_by_component(component_ids, SBOM.BomType.SBOM)
    chosen = {c["id"]: newest_cbom.get(c["id"]) or newest_sbom.get(c["id"]) for c in components}

    runs = (
        AssessmentRun.objects.filter(
            sbom_id__in=[sbom_id for sbom_id in chosen.values() if sbom_id],
            plugin_name=PQC_PLUGIN,
            status="completed",
        )
        .order_by("sbom_id", "-created_at")
        .distinct("sbom_id")
        .values("sbom_id", "result", "created_at")
    )
    run_by_sbom = {str(run["sbom_id"]): run for run in runs}

    rows: list[dict[str, Any]] = []
    verdict_counts: Counter[str] = Counter()
    vulnerable_components: dict[str, set[str]] = {}
    certs_total = {"expired": 0, "expiring_soon": 0}
    for component in components:
        sbom_id = chosen[component["id"]]
        run = run_by_sbom.get(str(sbom_id)) if sbom_id else None
        row: dict[str, Any] = {
            "id": component["id"],
            "name": component["name"],
            "sbom_id": sbom_id,
            "verdict": "not_assessed",
            "counts": {"quantum_vulnerable": 0, "review": 0, "unknown": 0, "quantum_safe": 0},
            "certificates": None,
            "assessed_at": None,
        }
        if run:
            result = run["result"] if isinstance(run["result"], dict) else {}
            raw_metadata = result.get("metadata")
            metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
            row["assessed_at"] = run["created_at"]
            if metadata.get("skipped"):
                row["verdict"] = "no_crypto"
            else:
                row["verdict"] = metadata.get("pqc_overall") or "not_assessed"
                for finding in result.get("findings") or []:
                    if not isinstance(finding, dict):
                        continue
                    raw_finding_meta = finding.get("metadata")
                    finding_meta: dict[str, Any] = raw_finding_meta if isinstance(raw_finding_meta, dict) else {}
                    status = finding_meta.get("pqc_status")
                    if status in row["counts"]:
                        row["counts"][status] += 1
                    if status == "quantum_vulnerable":
                        name = finding_meta.get("asset_name") or str(finding.get("title", "")).split(" — ")[0]
                        if name:
                            vulnerable_components.setdefault(name, set()).add(component["id"])
                certificates = metadata.get("certificates")
                if isinstance(certificates, dict):
                    row["certificates"] = certificates
                    certs_total["expired"] += int(certificates.get("expired") or 0)
                    certs_total["expiring_soon"] += int(certificates.get("expiring_soon") or 0)
        verdict_counts[row["verdict"]] += 1
        rows.append(row)

    rows.sort(key=lambda r: (_VERDICT_ORDER.get(r["verdict"], 4), r["name"].lower()))
    ranked: list[tuple[str, int]] = sorted(
        ((name, len(ids)) for name, ids in vulnerable_components.items()),
        key=lambda entry: (-entry[1], entry[0]),
    )[:10]
    top_vulnerable = [{"name": name, "components": count} for name, count in ranked]
    return {
        "rows": rows,
        "verdict_counts": dict(verdict_counts),
        "top_vulnerable": top_vulnerable,
        "certificates": certs_total,
        "has_crypto_data": any(r["verdict"] in ("at_risk", "needs_review", "ready") for r in rows),
    }
