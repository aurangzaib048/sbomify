"""Crypto UX surfaces: interpreted certificate/protocol views, replacement
suggestions, the inventory-card drill-down, and the cipher-suite CSV export."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from pytest_mock.plugin import MockerFixture

from ..crypto_inventory import CryptoAsset
from ..models import SBOM
from ..pqc import PqcStatus, replacement_for
from ..services.sboms import _certificate_view, _protocol_view
from .fixtures import sample_component, sample_sbom  # noqa: F401
from .test_views import setup_test_session

_DATA = Path(__file__).parent / "test_data"
_S3_TARGET = "sbomify.apps.sboms.services.sboms.S3Client"


def _algo(name: str, **kw) -> CryptoAsset:
    return CryptoAsset(name=name, bom_ref=None, oid=None, asset_type="algorithm", **kw)


def test_certificate_view_expiry_countdown():
    soon = (timezone.now() + timedelta(days=30)).isoformat()
    view = _certificate_view({"subjectName": "CN=a", "issuerName": "CN=ca", "notValidAfter": soon})
    assert view is not None
    assert view["expiring_soon"] and not view["expired"]
    assert 28 <= view["days_to_expiry"] <= 30

    past = (timezone.now() - timedelta(days=5)).isoformat()
    expired = _certificate_view({"notValidAfter": past})
    assert expired is not None and expired["expired"]


def test_certificate_view_states_tolerate_shapes():
    view = _certificate_view({"certificateState": [{"state": "active"}, "revoked", {"name": "custom"}]})
    assert view is not None
    assert view["states"] == ["active", "revoked", "custom"]


def test_protocol_view_flags_weak_suites_and_versions():
    view = _protocol_view(
        {
            "type": "tls",
            "version": "1.1",
            "cipherSuites": [
                {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "identifiers": ["0x00,0x0A"]},
                {"name": "TLS_AES_128_GCM_SHA256"},
            ],
        }
    )
    assert view is not None
    assert view["weak_version"] and "RFC 8996" in view["weak_version"]
    by_name = {s["name"]: s for s in view["cipher_suites"]}
    assert by_name["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]["weaknesses"]
    assert by_name["TLS_AES_128_GCM_SHA256"]["weaknesses"] == []


def test_protocol_view_reads_legacy_tls_cipher_suites():
    view = _protocol_view({"type": "tls", "version": "1.2", "tlsCipherSuites": ["TLS_RSA_WITH_RC4_128_MD5"]})
    assert view is not None
    assert view["weak_version"] is None
    assert view["cipher_suites"][0]["weaknesses"]  # RC4 + MD5


def test_replacement_targets_follow_primitive():
    assert "ML-DSA" in (replacement_for(_algo("ECDSA-P256"), PqcStatus.VULNERABLE) or "")
    assert replacement_for(_algo("X25519"), PqcStatus.VULNERABLE) == "ML-KEM (FIPS 203)"
    combined = replacement_for(_algo("RSA-2048"), PqcStatus.VULNERABLE) or ""
    assert "ML-KEM" in combined and "ML-DSA" in combined
    assert replacement_for(_algo("AES-256"), PqcStatus.SAFE) is None


@pytest.mark.django_db
def test_inventory_card_renders_tabs_and_drilldown(sample_sbom: SBOM, mocker: MockerFixture):  # noqa: F811
    mocker.patch(_S3_TARGET).return_value.get_sbom_data.return_value = (_DATA / "cbom_sample_1.6.cdx.json").read_bytes()
    client = Client()
    team = sample_sbom.component.team
    setup_test_session(client, team, team.members.first())

    response = client.get(reverse("sboms:sbom_crypto_inventory", kwargs={"sbom_id": sample_sbom.id}))

    assert response.status_code == 200
    html = response.content.decode()
    assert "Cryptographic Assets" in html
    assert "Certificates" in html  # the 1.6 fixture carries a certificate
    assert "Protocols" in html
    assert "Export CSV" in html
    assert "CN=demo.example.com" in html
    assert "Replacement:" in html  # vulnerable assets carry a migration target


@pytest.mark.django_db
def test_cipher_suite_csv_download(sample_sbom: SBOM, mocker: MockerFixture):  # noqa: F811
    mocker.patch(_S3_TARGET).return_value.get_sbom_data.return_value = (_DATA / "cbom_sample_1.6.cdx.json").read_bytes()
    client = Client()
    team = sample_sbom.component.team
    setup_test_session(client, team, team.members.first())

    url = reverse("api-1:download_cipher_suite_inventory_csv", kwargs={"sbom_id": sample_sbom.id})
    response = client.get(url)

    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/csv")
    body = response.content.decode()
    assert body.splitlines()[0] == "protocol,type,version,cipher_suite,identifiers,weak,weaknesses"
    assert "TLS" in body
