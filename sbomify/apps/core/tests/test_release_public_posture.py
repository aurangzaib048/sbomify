"""The public (Trust Center) release page renders the vulnerability posture card
when the release has scanned SBOMs."""

from __future__ import annotations

import pytest
from django.test import Client
from django.urls import reverse

from sbomify.apps.core.models import Component, Product, Release, ReleaseArtifact
from sbomify.apps.plugins.models import AssessmentRun
from sbomify.apps.sboms.models import SBOM


def _public_release_with_scan(team):
    product = Product.objects.create(name="Public P", team=team, is_public=True)
    release = Release.objects.create(product=product, name="v1.0.0")
    component = Component.objects.create(name="c", team=team)
    sbom = SBOM.objects.create(
        name="app", format="cyclonedx", format_version="1.6", sbom_filename="app.json", component=component
    )
    ReleaseArtifact.objects.create(release=release, sbom=sbom)
    AssessmentRun.objects.create(
        sbom=sbom,
        plugin_name="osv",
        plugin_version="1.0.0",
        category="security",
        status="completed",
        result={
            "findings": [
                {"id": "CVE-2026-1", "severity": "high", "component": {"name": "foo"}},
                {
                    "id": "CVE-2026-2",
                    "severity": "critical",
                    "component": {"name": "bar"},
                    "analysis_state": "not_affected",
                    "analysis_justification": "code_not_reachable",
                },
            ],
            "summary": {"by_severity": {"high": 1}, "total_findings": 1, "suppressed_count": 1},
        },
    )
    return product, release


@pytest.mark.django_db
def test_public_release_page_shows_vuln_posture(sample_team_with_owner_member):
    product, release = _public_release_with_scan(sample_team_with_owner_member.team)
    url = reverse("core:release_details_public", kwargs={"product_id": product.id, "release_id": release.id})

    resp = Client().get(url)

    assert resp.status_code == 200
    html = resp.content.decode()
    # The posture card and its embedded data are present.
    assert "Vulnerability Posture" in html
    assert 'id="vuln-posture-data"' in html
    # Data carries both raw and VEX-applied counts plus the suppressed finding.
    assert "CVE-2026-1" in html
    assert "not_affected" in html
    assert '"suppressed_count": 1' in html


@pytest.mark.django_db
def test_public_release_page_no_posture_without_scans(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    product = Product.objects.create(name="Empty P", team=team, is_public=True)
    release = Release.objects.create(product=product, name="v1.0.0")
    url = reverse("core:release_details_public", kwargs={"product_id": product.id, "release_id": release.id})

    resp = Client().get(url)

    assert resp.status_code == 200
    assert "Vulnerability Posture" not in resp.content.decode()
