from __future__ import annotations

from typing import Any

from django.http import HttpRequest

from sbomify.apps.core.apis import get_component, list_component_sboms
from sbomify.apps.core.services.results import ServiceResult
from sbomify.apps.core.utils import number_to_random_token
from sbomify.apps.plugins.models import AssessmentRun
from sbomify.apps.sboms.forms import SbomDeleteForm
from sbomify.apps.sboms.services.sboms import delete_sbom_record
from sbomify.apps.teams.apis import get_team
from sbomify.apps.vulnerability_scanning.utils import extract_severity_counts


def _attach_vulnerability_counts(sbom_items: list[dict[str, Any]]) -> None:
    """Attach each SBOM's latest security-scan severity counts as ``item['vuln']``.

    One batched query over every SBOM in the table. Ordering newest-first per
    ``sbom_id`` means the first row seen for a given SBOM is its latest run, so
    the counts read straight off that run (VEX-suppressed findings are already
    excluded from the stored summary). Rows with no completed security run get
    ``vuln = None``, which the table renders as "not scanned".
    """
    sbom_ids = [item["sbom"]["id"] for item in sbom_items if item.get("sbom", {}).get("id")]
    if not sbom_ids:
        return

    # DISTINCT ON (sbom_id) with newest-first ordering returns exactly one row
    # per SBOM — its latest run — so we never load every historical result blob.
    latest_runs = (
        AssessmentRun.objects.filter(sbom_id__in=sbom_ids, category="security", status="completed")
        .order_by("sbom_id", "-created_at")
        .distinct("sbom_id")
        .values("sbom_id", "result")
    )
    latest_by_sbom: dict[str, dict[str, int]] = {
        str(run["sbom_id"]): extract_severity_counts(run["result"]) for run in latest_runs
    }

    for item in sbom_items:
        item["vuln"] = latest_by_sbom.get(str(item.get("sbom", {}).get("id", "")))


def _summary_artifacts(sbom_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The compact card view: the newest artifact of each non-VEX type, plus the
    newest VEX *per source*.

    VEX resolution is latest-wins per source (a newer dependency-track export
    supersedes the older one; an in-app triage document supersedes earlier triage
    versions), so the card lists exactly the documents that make up the effective
    posture — one per source — rather than every historical VEX. The full history
    lives behind the "View all" toggle (``?full=1``).
    """
    by_date = sorted(
        sbom_items,
        key=lambda x: x["sbom"]["created_at"].timestamp() if x["sbom"].get("created_at") else 0.0,
        reverse=True,
    )
    seen_types: set[str] = set()
    seen_vex_sources: set[str] = set()
    summary: list[dict[str, Any]] = []
    for item in by_date:
        bom_type = item["sbom"].get("bom_type") or "sbom"
        if bom_type == "vex":
            source = item["sbom"].get("source") or ""
            if source not in seen_vex_sources:
                seen_vex_sources.add(source)
                summary.append(item)
        elif bom_type not in seen_types:
            seen_types.add(bom_type)
            summary.append(item)
    return summary


def build_sboms_table_context(
    request: HttpRequest, component_id: str, is_public_view: bool
) -> ServiceResult[dict[str, Any]]:
    status_code, component = get_component(request, component_id)
    if status_code != 200:
        return ServiceResult.failure(component.get("detail", "Unknown error"))

    status_code, sboms = list_component_sboms(request, component_id, page=1, page_size=-1, include_all_types=True)
    if status_code != 200:
        return ServiceResult.failure(sboms.get("detail", "Failed to load SBOMs"))

    sbom_items = sboms.get("items", [])

    # Sort SBOMs by name (alphabetically) then by created_at (newest first)
    sbom_items = sorted(
        sbom_items,
        key=lambda x: (
            x["sbom"]["name"].lower(),
            -x["sbom"]["created_at"].timestamp() if x["sbom"]["created_at"] else 0,
        ),
    )

    # ``assessments`` is already populated by ``list_component_sboms`` from a
    # single batched query (including ``skipped_count``), so no per-SBOM
    # enrichment loop is needed here. The earlier
    # ``get_sbom_assessment_badge``-per-row loop reissued the same latest-runs
    # subquery and display-name lookup that the batched API path had already
    # done — ~3 extra queries per row on top of the inner N+1 — and was the
    # dominant slow path on the component detail page.

    # The component card shows only the latest artifact of each type; ?full=1
    # (the "View all" toggle) returns the complete history.
    full_view = request.GET.get("full") == "1"
    total_artifact_count = len(sbom_items)
    if not full_view:
        sbom_items = _summary_artifacts(sbom_items)

    if not is_public_view:
        _attach_vulnerability_counts(sbom_items)

    context = {
        "component_id": component_id,
        "sboms": sbom_items,
        "is_public_view": is_public_view,
        "has_crud_permissions": component.get("has_crud_permissions", False),
        "full_view": full_view,
        "show_view_all": not full_view and total_artifact_count > len(sbom_items),
        "total_artifact_count": total_artifact_count,
    }

    if not is_public_view:
        team_key = number_to_random_token(component.get("team_id"))
        status_code, team = get_team(request, team_key)
        if status_code != 200:
            return ServiceResult.failure(team.get("detail", "Failed to load team"))

        context.update(
            {
                "team_billing_plan": team.billing_plan,
                "team_key": team_key,
                "delete_form": SbomDeleteForm(),
            }
        )

    return ServiceResult.success(context)


def delete_sbom_from_request(request: HttpRequest) -> ServiceResult[None]:
    form = SbomDeleteForm(request.POST)
    if not form.is_valid():
        return ServiceResult.failure(form.errors.as_text())

    result = delete_sbom_record(request, form.cleaned_data["sbom_id"])
    if not result.ok:
        return ServiceResult.failure(result.error or "Failed to delete SBOM", status_code=result.status_code)

    return ServiceResult.success()
