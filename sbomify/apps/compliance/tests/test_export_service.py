"""Tests for the CRA export service — ZIP packaging."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sbomify.apps.compliance.models import CRAExportPackage
from sbomify.apps.compliance.services.document_generation_service import regenerate_all
from sbomify.apps.compliance.services.export_service import build_export_package, get_download_url
from sbomify.apps.compliance.services.wizard_service import get_or_create_assessment
from sbomify.apps.core.models import Product
from sbomify.apps.teams.models import ContactEntity, ContactProfile, ContactProfileContact


@pytest.fixture
def product(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    return Product.objects.create(name="Export Test Product", team=team)


@pytest.fixture
def assessment(sample_team_with_owner_member, sample_user, product):
    team = sample_team_with_owner_member.team

    profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
    entity = ContactEntity.objects.create(
        profile=profile,
        name="Acme Corp",
        email="info@acme.test",
        address="123 Test St",
        is_manufacturer=True,
    )
    ContactProfileContact.objects.create(
        entity=entity,
        name="Security Lead",
        email="security@acme.test",
        is_security_contact=True,
    )

    result = get_or_create_assessment(product.id, sample_user, team)
    assert result.ok
    return result.value


@pytest.fixture
def assessment_with_docs(assessment):
    """Assessment with all documents generated."""
    with patch("sbomify.apps.core.object_store.S3Client"):
        regenerate_all(assessment)
    return assessment


@pytest.mark.django_db
class TestBuildExportPackage:
    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_creates_package_record(self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user):
        mock_get_content.return_value = b"mock document content"

        result = build_export_package(assessment_with_docs, sample_user)

        assert result.ok
        package = result.value
        assert isinstance(package, CRAExportPackage)
        assert package.content_hash
        assert package.manifest is not None
        assert package.manifest["cra_regulation"] == "EU 2024/2847"
        assert package.manifest["product"]["name"] == "Export Test Product"
        assert package.manifest["manufacturer"]["name"] == "Acme Corp"

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_manifest_contains_file_entries(self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user):
        mock_get_content.return_value = b"mock document content"

        result = build_export_package(assessment_with_docs, sample_user)

        assert result.ok
        files = result.value.manifest["files"]
        paths = [f["path"] for f in files]

        # OSCAL files always present
        assert any("oscal/catalog.json" in p for p in paths)
        assert any("oscal/assessment-results.json" in p for p in paths)
        # Manifest is NOT included in its own files list to avoid
        # inconsistency between the DB manifest and the in-ZIP manifest.
        assert not any("metadata/manifest.json" in p for p in paths)

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_manifest_files_have_sha256(self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user):
        mock_get_content.return_value = b"mock document content"

        result = build_export_package(assessment_with_docs, sample_user)

        for file_entry in result.value.manifest["files"]:
            assert "sha256" in file_entry
            assert len(file_entry["sha256"]) == 64

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_oscal_catalog_in_package(self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user):
        """OSCAL catalog JSON should be included in the package."""
        mock_get_content.return_value = b"mock content"

        result = build_export_package(assessment_with_docs, sample_user)
        assert result.ok

        # Verify catalog is referenced in manifest
        files = result.value.manifest["files"]
        catalog_entries = [f for f in files if "catalog.json" in f["path"]]
        assert len(catalog_entries) == 1

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_product_category_in_manifest(self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user):
        mock_get_content.return_value = b"mock content"

        result = build_export_package(assessment_with_docs, sample_user)
        assert result.value.manifest["product_category"] == "default"
        assert result.value.manifest["conformity_procedure"] == "module_a"

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_bundle_contains_harmonised_standards_reference(
        self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user
    ):
        """The bundle must embed the harmonised-standards mapping so
        downstream auditors don't need to chase it in the sbomify repo."""
        mock_get_content.return_value = b"mock content"

        result = build_export_package(assessment_with_docs, sample_user)
        paths = [f["path"] for f in result.value.manifest["files"]]
        assert any("metadata/harmonised-standards.json" in p for p in paths)

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_bundle_contains_article_14_reporting_readme(
        self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user
    ):
        """README documents the 2026-09-11 deadline + SRP submission
        channel so operators don't misread Article 14 obligations."""
        mock_get_content.return_value = b"mock content"

        result = build_export_package(assessment_with_docs, sample_user)
        paths = [f["path"] for f in result.value.manifest["files"]]
        assert any("article-14/README_REPORTING.md" in p for p in paths)

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_manifest_declares_integrity_metadata(
        self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user
    ):
        """Manifest self-describes its integrity regime: hash algorithm
        plus the paths of manifest.sha256 and INTEGRITY.md."""
        mock_get_content.return_value = b"mock content"

        result = build_export_package(assessment_with_docs, sample_user)
        integrity = result.value.manifest.get("integrity")
        assert integrity is not None
        assert integrity["hash_algorithm"] == "sha256"
        assert integrity["manifest_hash_file"] == "metadata/manifest.sha256"
        assert integrity["verification_doc"] == "metadata/INTEGRITY.md"

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_bundle_contains_manifest_self_hash_and_integrity_doc(
        self, mock_get_content, mock_s3_cls, assessment_with_docs, sample_user
    ):
        """ZIP must physically carry ``manifest.sha256`` and
        ``INTEGRITY.md`` — verified by extracting the uploaded bytes.
        The S3 upload is mocked so we introspect the call payload."""
        import io
        import zipfile

        mock_get_content.return_value = b"mock content"

        captured: dict[str, bytes] = {}

        class _Capture:
            def upload_data_as_file(self, bucket, key, data):
                captured["bytes"] = data

            def get_file_data(self, bucket, key):  # pragma: no cover - unused path
                return b""

            def get_sbom_data(self, filename):  # pragma: no cover - unused path
                return b""

        mock_s3_cls.return_value = _Capture()

        result = build_export_package(assessment_with_docs, sample_user)
        assert result.ok
        assert "bytes" in captured, "S3 upload was not invoked"

        with zipfile.ZipFile(io.BytesIO(captured["bytes"])) as zf:
            names = zf.namelist()
            assert any(n.endswith("metadata/manifest.sha256") for n in names)
            assert any(n.endswith("metadata/INTEGRITY.md") for n in names)
            # Self-hash must match the in-ZIP manifest exactly.
            manifest_name = next(n for n in names if n.endswith("metadata/manifest.json"))
            sha_name = next(n for n in names if n.endswith("metadata/manifest.sha256"))
            import hashlib

            expected = hashlib.sha256(zf.read(manifest_name)).hexdigest()
            assert expected in zf.read(sha_name).decode("utf-8")

    @patch("sbomify.apps.compliance.services.export_service.S3Client")
    @patch("sbomify.apps.compliance.services.export_service._get_generated_doc_content")
    def test_manifest_flags_placeholder_manufacturer(
        self, mock_get_content, mock_s3_cls, sample_team_with_owner_member, sample_user
    ):
        """Manifest surface carries ``is_placeholder`` so a downstream
        consumer (notified body, auditor, CI gate) can reject a bundle
        that still has a stub manufacturer."""
        team = sample_team_with_owner_member.team
        profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
        ContactEntity.objects.create(
            profile=profile,
            name="ABC",  # obvious placeholder
            email="info@abc.test",
            address="",
            is_manufacturer=True,
        )
        p = Product.objects.create(name="Placeholder Export", team=team)
        ares = get_or_create_assessment(p.id, sample_user, team)
        with patch("sbomify.apps.core.object_store.S3Client"):
            regenerate_all(ares.value)
        mock_get_content.return_value = b"mock content"

        result = build_export_package(ares.value, sample_user)
        assert result.ok
        mfr = result.value.manifest["manufacturer"]
        assert mfr["is_placeholder"] is True


@pytest.mark.django_db
class TestGetDownloadUrl:
    def test_generates_presigned_url(self):
        mock_package = MagicMock()
        mock_package.storage_key = "compliance/exports/test/abc.zip"

        with patch("boto3.client") as mock_client_fn:
            mock_s3 = MagicMock()
            mock_s3.generate_presigned_url.return_value = "https://s3.example.com/presigned"
            mock_client_fn.return_value = mock_s3

            result = get_download_url(mock_package)

        assert result.ok
        assert result.value == "https://s3.example.com/presigned"

    def test_handles_s3_error(self):
        mock_package = MagicMock()
        mock_package.storage_key = "bad-key"

        with patch("boto3.client") as mock_client_fn:
            mock_client_fn.side_effect = Exception("S3 error")

            result = get_download_url(mock_package)

        assert not result.ok
        assert result.status_code == 500
