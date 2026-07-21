from __future__ import annotations

from typing import Any

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views import View

from sbomify.apps.core.apis import get_component
from sbomify.apps.core.errors import error_response
from sbomify.apps.teams.permissions import GuestAccessBlockedMixin


class ComponentDetailsPrivateView(GuestAccessBlockedMixin, LoginRequiredMixin, View):
    def dispatch(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        # On custom domains, serve public content instead
        if getattr(request, "is_custom_domain", False):
            from sbomify.apps.core.views.component_details_public import ComponentDetailsPublicView

            return ComponentDetailsPublicView.as_view()(request, *args, **kwargs)
        return super().dispatch(request, *args, **kwargs)

    def get(self, request: HttpRequest, component_id: str) -> HttpResponse:
        status_code, component = get_component(request, component_id)
        if status_code != 200:
            return error_response(
                request, HttpResponse(status=status_code, content=component.get("detail", "Unknown error"))
            )

        current_team = request.session.get("current_team", {})
        is_owner = current_team.get("role") == "owner"
        billing_plan = current_team.get("billing_plan")

        # Get company NDA ID for visibility selector and check if gated visibility is allowed
        company_nda_id = None
        gated_visibility_allowed = False
        team_key = current_team.get("key")
        team_id = component.get("team_id")
        if team_id:
            from sbomify.apps.teams.models import Team

            try:
                team = Team.objects.get(pk=team_id)
                if not team_key:
                    team_key = team.key
                company_nda = team.get_company_nda_document()
                if company_nda:
                    company_nda_id = company_nda.id
                # Check if gated visibility is allowed (Business or Enterprise plans)
                gated_visibility_allowed = team.can_be_private()
            except Team.DoesNotExist:
                # If the referenced team no longer exists, keep the previously initialized
                # default values (no NDA, no gated visibility) and continue rendering.
                pass

        # Build mapping of document types to their subcategory choices for dynamic dropdowns
        import json

        from sbomify.apps.documents.models import Document

        document_type_subcategories = {}
        for doc_type_value, doc_type_label in Document.DocumentType.choices:
            if doc_type_value == Document.DocumentType.COMPLIANCE:
                document_type_subcategories[doc_type_value] = {
                    "field_name": "compliance_subcategory",
                    "choices": Document.ComplianceSubcategory.choices,
                    "label": "Compliance Subcategory",
                }
            # Add more document types with subcategories here as needed

        # Latest-scan vulnerability summary for the header badge: the newest SBOM's
        # most recent completed security run (VEX-suppressed findings already
        # excluded). Tied to the newest SBOM so it matches the top artifacts row,
        # rather than whichever run happened to complete last.
        from sbomify.apps.plugins.models import AssessmentRun
        from sbomify.apps.sboms.models import SBOM
        from sbomify.apps.vulnerability_scanning.utils import extract_finding_rows, extract_severity_counts
        from sbomify.apps.vulnerability_scanning.vex import load_vex_suppressions

        latest_sbom = (
            SBOM.objects.filter(component_id=component_id, bom_type=SBOM.BomType.SBOM)
            .order_by("-created_at")
            .values("id", "version")
            .first()
        )
        latest_sbom_id = latest_sbom["id"] if latest_sbom else None
        latest_scan_result = (
            (
                AssessmentRun.objects.filter(sbom_id=latest_sbom_id, category="security", status="completed")
                .order_by("-created_at")
                .values_list("result", flat=True)
                .first()
            )
            if latest_sbom_id
            else None
        )
        vuln_summary = extract_severity_counts(latest_scan_result) if latest_scan_result else None
        # Flat, severity-sorted findings for the latest SBOM's drill-down table.
        # Pass the component's VEX so each finding's status resolves live, even
        # when the stored scan predates the VEX upload.
        vex_statements = load_vex_suppressions(component_id) if latest_scan_result else []
        latest_vulns = extract_finding_rows(latest_scan_result, vex_statements) if latest_scan_result else []
        # Lowercased "advisory package ecosystem" haystack per finding, so the
        # drill-down's search box can filter client-side without re-fetching.
        latest_vuln_terms = [f"{v['id']} {v['package']} {v['ecosystem']}".lower() for v in latest_vulns]

        context = {
            "APP_BASE_URL": settings.APP_BASE_URL,
            "component": component,
            "current_team": current_team,
            "is_owner": is_owner,
            "team_billing_plan": billing_plan,
            "company_nda_id": company_nda_id,
            "gated_visibility_allowed": gated_visibility_allowed,
            "team_key": team_key,
            "vuln_summary": vuln_summary,
            "latest_vulns": latest_vulns,
            "latest_vuln_terms": latest_vuln_terms,
            "latest_vuln_version": latest_sbom["version"] if latest_sbom else None,
            "latest_vuln_sbom_id": latest_sbom_id,
            "document_type_subcategories": document_type_subcategories,
            "document_type_subcategories_json": json.dumps(document_type_subcategories),
        }

        component_type = component.get("component_type")
        if component_type == "bom":
            template_name = "core/component_details_private_sbom.html.j2"
        elif component_type == "document":
            template_name = "core/component_details_private_document.html.j2"
        else:
            return error_response(request, HttpResponse(status=400, content="Invalid component type"))

        return render(request, template_name, context)
