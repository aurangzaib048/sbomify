"""Merged release-level CBOM: one crypto BOM per release, built from the CBOM
artifacts pinned in the release's slots, gated like the SBOM/VEX downloads."""

from __future__ import annotations

import json

import pytest
from django.core.cache import cache
from django.test import Client
from django.urls import reverse

from sbomify.apps.core.models import Component, Product, Release, ReleaseArtifact
from sbomify.apps.sboms.cbom import build_release_cbom
from sbomify.apps.sboms.models import SBOM


def _release_with_components(team, *, is_public: bool):
    product = Product.objects.create(name="P", team=team, is_public=is_public)
    release = Release.objects.create(product=product, name="v1")
    c1 = Component.objects.create(name="c1", team=team)
    c2 = Component.objects.create(name="c2", team=team)
    return product, release, c1, c2


def _cbom_sbom(component, filename: str) -> SBOM:
    return SBOM.objects.create(
        name=f"cbom-{filename}",
        format="cyclonedx",
        format_version="1.6",
        sbom_filename=filename,
        component=component,
        bom_type=SBOM.BomType.CBOM,
    )


def _doc(ref: str) -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"type": "cryptographic-asset", "bom-ref": ref, "name": ref.split("/")[-1]}],
        }
    ).encode()


def _mock_s3(mocker, docs_by_filename: dict[str, bytes]):
    s3 = mocker.patch("sbomify.apps.core.object_store.S3Client")
    s3.return_value.get_sbom_data.side_effect = lambda filename: docs_by_filename[filename]
    return s3


@pytest.mark.django_db
def test_build_release_cbom_merges_slot_documents(sample_team_with_owner_member, mocker):
    team = sample_team_with_owner_member.team
    _product, release, c1, c2 = _release_with_components(team, is_public=True)
    ReleaseArtifact.objects.create(release=release, sbom=_cbom_sbom(c1, "c1.cbom.json"))
    ReleaseArtifact.objects.create(release=release, sbom=_cbom_sbom(c2, "c2.cbom.json"))
    _mock_s3(mocker, {"c1.cbom.json": _doc("crypto/a"), "c2.cbom.json": _doc("crypto/b")})

    merged = build_release_cbom(release)

    assert merged is not None
    assert {c["bom-ref"] for c in merged["components"]} == {"crypto/a", "crypto/b"}


@pytest.mark.django_db
def test_build_release_cbom_none_without_slot(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    _product, release, _c1, _c2 = _release_with_components(team, is_public=True)
    assert build_release_cbom(release) is None


@pytest.mark.django_db
def test_download_release_cbom_public_returns_attachment(sample_team_with_owner_member, mocker):
    team = sample_team_with_owner_member.team
    _product, release, c1, _c2 = _release_with_components(team, is_public=True)
    ReleaseArtifact.objects.create(release=release, sbom=_cbom_sbom(c1, "c1.cbom.json"))
    _mock_s3(mocker, {"c1.cbom.json": _doc("crypto/a")})
    cache.clear()

    resp = Client().get(reverse("api-1:download_release_cbom", kwargs={"release_id": release.id}))

    assert resp.status_code == 200
    assert "attachment" in resp["Content-Disposition"]
    assert resp["Content-Disposition"].endswith(".cbom.cdx.json")


@pytest.mark.django_db
def test_download_release_cbom_404_when_absent(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    _product, release, _c1, _c2 = _release_with_components(team, is_public=True)
    cache.clear()
    resp = Client().get(reverse("api-1:download_release_cbom", kwargs={"release_id": release.id}))
    assert resp.status_code == 404


@pytest.mark.django_db
def test_download_release_cbom_private_requires_auth(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    _product, release, _c1, _c2 = _release_with_components(team, is_public=False)
    resp = Client().get(reverse("api-1:download_release_cbom", kwargs={"release_id": release.id}))
    assert resp.status_code == 403
