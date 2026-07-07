"""The stored `version` for a VEX row keys on the document serialNumber so daily re-issues against
the same release do not collide on the SBOM uniqueness constraint."""

from __future__ import annotations

from sbomify.apps.sboms.utils import vex_row_version


def test_uses_serial_number_when_present() -> None:
    assert vex_row_version({"serialNumber": "urn:uuid:abc"}, "deadbeef") == "urn:uuid:abc"
    assert vex_row_version({"serialNumber": "  urn:uuid:abc  "}, "deadbeef") == "urn:uuid:abc"


def test_falls_back_to_content_hash_without_serial() -> None:
    assert vex_row_version({}, "deadbeef") == "sha256:deadbeef"
    assert vex_row_version({"serialNumber": ""}, "deadbeef") == "sha256:deadbeef"
    assert vex_row_version({"serialNumber": "   "}, "deadbeef") == "sha256:deadbeef"


def test_two_dt_exports_get_distinct_versions() -> None:
    # Dependency-Track sets a fresh serialNumber per export, so two daily re-issues against the same
    # release get distinct stored versions and neither 409s the other.
    v1 = vex_row_version({"serialNumber": "urn:uuid:11111111"}, "h1")
    v2 = vex_row_version({"serialNumber": "urn:uuid:22222222"}, "h2")
    assert v1 != v2


def test_identical_document_dedupes() -> None:
    # A re-upload of the exact same document (same serialNumber) yields the same version, so the
    # uniqueness constraint correctly rejects it as a duplicate.
    doc = {"serialNumber": "urn:uuid:33333333"}
    assert vex_row_version(doc, "h") == vex_row_version(doc, "h")
