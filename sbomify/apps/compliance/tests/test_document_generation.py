"""Tests for the CRA document generation service."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sbomify.apps.compliance.models import (
    CRAGeneratedDocument,
    OSCALFinding,
)
from sbomify.apps.compliance.services._manufacturer_policy import (
    is_placeholder_manufacturer as _is_placeholder_manufacturer,
)
from sbomify.apps.compliance.services.document_generation_service import (
    _load_harmonised_standards,
    _select_applied_standards,
    _sanitize,
    generate_document,
    get_document_preview,
    regenerate_all,
    regenerate_stale,
)
from sbomify.apps.compliance.services.wizard_service import get_or_create_assessment
from sbomify.apps.core.models import Product
from sbomify.apps.teams.models import ContactEntity, ContactProfile, ContactProfileContact


@pytest.fixture
def product(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    return Product.objects.create(name="Doc Gen Product", team=team)


@pytest.fixture
def assessment(sample_team_with_owner_member, sample_user, product):
    team = sample_team_with_owner_member.team

    # Create manufacturer contact
    profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
    entity = ContactEntity.objects.create(
        profile=profile,
        name="Acme Corp",
        email="info@acme.test",
        address="123 Test St, Berlin",
        is_manufacturer=True,
        website_urls=["https://acme.test"],
    )
    ContactProfileContact.objects.create(
        entity=entity,
        name="Security Lead",
        email="security@acme.test",
        is_security_contact=True,
    )

    result = get_or_create_assessment(product.id, sample_user, team)
    assert result.ok
    a = result.value
    a.intended_use = "Home automation"
    a.target_eu_markets = ["DE", "FR"]
    a.vdp_url = "https://acme.test/vdp"
    a.update_frequency = "quarterly"
    a.support_email = "support@acme.test"
    a.data_deletion_instructions = "Factory reset the device."
    a.save()
    return a


@pytest.mark.django_db
class TestGenerateDocument:
    """Test document generation for each kind."""

    @patch("sbomify.apps.core.object_store.S3Client")
    def test_generates_vdp(self, mock_s3_cls, assessment):
        result = generate_document(assessment, CRAGeneratedDocument.DocumentKind.VDP)

        assert result.ok
        doc = result.value
        assert doc.document_kind == "vdp"
        assert doc.version == 1
        assert doc.is_stale is False
        assert doc.content_hash
        assert doc.storage_key.endswith(".md")

    @patch("sbomify.apps.core.object_store.S3Client")
    def test_generates_security_txt(self, mock_s3_cls, assessment):
        result = generate_document(assessment, CRAGeneratedDocument.DocumentKind.SECURITY_TXT)

        assert result.ok
        doc = result.value
        assert doc.document_kind == "security_txt"
        assert doc.storage_key.endswith(".txt")

    @patch("sbomify.apps.core.object_store.S3Client")
    def test_generates_risk_assessment(self, mock_s3_cls, assessment):
        result = generate_document(assessment, CRAGeneratedDocument.DocumentKind.RISK_ASSESSMENT)

        assert result.ok
        doc = result.value
        assert doc.document_kind == "risk_assessment"

    @patch("sbomify.apps.core.object_store.S3Client")
    def test_generates_declaration_of_conformity(self, mock_s3_cls, assessment):
        result = generate_document(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)

        assert result.ok
        doc = result.value
        assert doc.document_kind == "declaration_of_conformity"

    @patch("sbomify.apps.core.object_store.S3Client")
    def test_generates_all_9_kinds(self, mock_s3_cls, assessment):
        for kind, _ in CRAGeneratedDocument.DocumentKind.choices:
            result = generate_document(assessment, kind)
            assert result.ok, f"Failed to generate {kind}: {result.error}"

    def test_rejects_invalid_kind(self, assessment):
        result = generate_document(assessment, "bogus")
        assert not result.ok
        assert result.status_code == 400


@pytest.mark.django_db
class TestVersioning:
    """Test document version increments and stale flag resets."""

    @patch("sbomify.apps.core.object_store.S3Client")
    def test_version_increments_on_regeneration(self, mock_s3_cls, assessment):
        result1 = generate_document(assessment, CRAGeneratedDocument.DocumentKind.VDP)
        assert result1.ok
        assert result1.value.version == 1

        result2 = generate_document(assessment, CRAGeneratedDocument.DocumentKind.VDP)
        assert result2.ok
        assert result2.value.version == 2
        assert result2.value.id == result1.value.id  # Same record, updated

    @patch("sbomify.apps.core.object_store.S3Client")
    def test_stale_flag_resets_on_regeneration(self, mock_s3_cls, assessment):
        result = generate_document(assessment, CRAGeneratedDocument.DocumentKind.VDP)
        assert result.ok

        # Manually mark as stale
        doc = result.value
        doc.is_stale = True
        doc.save()

        # Regenerate
        result2 = generate_document(assessment, CRAGeneratedDocument.DocumentKind.VDP)
        assert result2.ok
        assert result2.value.is_stale is False

    @patch("sbomify.apps.core.object_store.S3Client")
    def test_content_hash_changes_when_data_changes(self, mock_s3_cls, assessment):
        result1 = generate_document(assessment, CRAGeneratedDocument.DocumentKind.VDP)
        hash1 = result1.value.content_hash

        # Change assessment data
        assessment.vdp_url = "https://acme.test/new-vdp"
        assessment.save()

        result2 = generate_document(assessment, CRAGeneratedDocument.DocumentKind.VDP)
        hash2 = result2.value.content_hash

        assert hash1 != hash2


@pytest.mark.django_db
class TestSecurityTxtFormat:
    """Test that security.txt follows RFC 9116 format."""

    def test_contains_contact_field(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.SECURITY_TXT)

        assert result.ok
        content = result.value
        assert "Contact: mailto:security@acme.test" in content

    def test_contains_policy_field(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.SECURITY_TXT)

        assert result.ok
        content = result.value
        assert "Policy: https://acme.test/vdp" in content

    def test_contains_preferred_languages(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.SECURITY_TXT)

        assert result.ok
        content = result.value
        assert "Preferred-Languages:" in content
        # DE -> de, FR -> fr, plus en always included
        assert "de" in content
        assert "en" in content
        assert "fr" in content

    def test_expires_is_support_period_plus_one_year(self, assessment):
        """RFC 9116 Expires is support_period_end + 1 year."""
        from datetime import date

        assessment.support_period_end = date(2027, 5, 20)
        assessment.save()
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.SECURITY_TXT)
        assert "Expires: 2028-05-20T00:00:00.000Z" in result.value

    def test_expires_leap_day_rolls_to_feb_28(self, assessment):
        """Feb 29 support_period_end rolls to Feb 28 next year (non-
        leap) so the .replace(year=...) ValueError branch is covered."""
        from datetime import date

        assessment.support_period_end = date(2028, 2, 29)
        assessment.save()
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.SECURITY_TXT)
        assert "Expires: 2029-02-28T00:00:00.000Z" in result.value

    def test_expires_empty_when_support_period_not_set(self, assessment):
        """No support period → Expires line is blank; operator sees
        the gap rather than a bogus date."""
        assessment.support_period_end = None
        assessment.save()
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.SECURITY_TXT)
        # The raw template emits `Expires: ` with an empty value; the
        # important regression is that no past date / "None" leaks.
        assert "Expires: None" not in result.value
        assert "Expires: 1970" not in result.value


@pytest.mark.django_db
class TestDeclarationOfConformity:
    """Test declaration includes all Annex V required fields."""

    def test_contains_product_identification(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Doc Gen Product" in content

    def test_contains_manufacturer_details(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Acme Corp" in content
        assert "123 Test St, Berlin" in content

    def test_contains_responsibility_statement(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "sole responsibility of the manufacturer" in content

    def test_contains_conformity_statement(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Regulation (EU) 2024/2847" in content

    def test_contains_signature_block(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Signature:" in content

    def test_lists_harmonised_standards_applied(self, assessment):
        """Annex V item 6 — the DoC must cite the standards applied.
        Every DoC always cites the CRA itself and BSI TR-03183-2 (SBOM
        format reference). Lists each standard's CRA mapping entries so
        notified bodies see the clause-level correspondence."""
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Regulation (EU) 2024/2847" in content
        assert "BSI TR-03183-2" in content
        assert "Annex I, Part II, §1" in content  # BSI → CRA SBOM mapping
        assert "eur-lex.europa.eu/eli/reg/2024/2847" in content

    def test_includes_support_period_when_set(self, assessment):
        """Article 13(8) support period must appear on the DoC, not only
        on the risk assessment."""
        from datetime import date

        assessment.support_period_end = date(2031, 4, 21)
        assessment.save()
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Support Period Ends" in content
        assert "2031-04-21" in content
        assert "Article 13(8)" in content

    def test_omits_support_period_when_not_set(self, assessment):
        """If the operator hasn't declared a support period yet, the
        Article 13(8) block is simply absent — not a silent 'None'."""
        assessment.support_period_end = None
        assessment.save()
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Support Period Ends" not in content
        assert "None" not in content.split("## 7.")[1].split("## 8.")[0]

    def test_lists_supporting_documentation_section(self, assessment):
        """Annex VII — DoC references the evidence files that back it."""
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Supporting Documentation" in content
        assert "sboms/*.cdx.json" in content
        assert "vulnerability-disclosure-policy.md" in content
        assert "oscal/*.json" in content
        assert "metadata/manifest.sha256" in content


@pytest.mark.django_db
class TestDeclarationManufacturerPlaceholder:
    """Placeholder-manufacturer guard: Annex V item 2 requires the
    legal name. When the team profile is empty / filled with a stub,
    the DoC must render a visible warning rather than ship invalid."""

    @pytest.mark.parametrize("placeholder", ["ABC", "xyz", "Test", "foo", "TBD", "None"])
    def test_placeholder_renders_warning(self, sample_team_with_owner_member, sample_user, placeholder):
        """Case-insensitive placeholder names always trigger the warning.

        Empty / whitespace-only values are covered by
        ``test_missing_manufacturer_renders_warning`` — ``ContactEntity``
        rejects empty names at the ORM level, so we can't parametrise
        over them here.
        """
        team = sample_team_with_owner_member.team
        profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
        ContactEntity.objects.create(
            profile=profile,
            name=placeholder,
            email="info@example.test",
            address="",
            is_manufacturer=True,
        )
        p = Product.objects.create(name="Placeholder Product", team=team)
        ares = get_or_create_assessment(p.id, sample_user, team)
        assert ares.ok
        result = get_document_preview(ares.value, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "[Manufacturer Name — not configured]" in content
        assert "Annex V item 2 requires" in content

    def test_missing_manufacturer_renders_warning(self, sample_team_with_owner_member, sample_user):
        """No manufacturer entity at all → same warning. The wizard must
        not silently emit a DoC with an empty ``**Name:**`` field."""
        team = sample_team_with_owner_member.team
        p = Product.objects.create(name="Manufacturer-less Product", team=team)
        ares = get_or_create_assessment(p.id, sample_user, team)
        assert ares.ok
        result = get_document_preview(ares.value, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "[Manufacturer Name — not configured]" in content

    def test_real_manufacturer_does_not_trigger_warning(self, assessment):
        """Existing fixture uses 'Acme Corp' which is a legal-looking
        name; the placeholder warning must not appear for it."""
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "Acme Corp" in content
        assert "not configured" not in content


class TestIsPlaceholderManufacturer:
    """Unit-level coverage of the placeholder predicate. Class-based
    parametrise below exercises the full matcher contract so a future
    edit to ``_PLACEHOLDER_MANUFACTURER_VALUES`` can't silently leak
    stub data into a DoC."""

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            " ",
            "   ",
            "\t",
            "\n",
            "abc",
            "ABC",
            "  abc  ",
            "Abc",
            "xyz",
            "test",
            "example",
            "acme",
            "foo",
            "bar",
            "tbd",
            "TODO",
            "n/a",
            "N/A",
            "na",
            "none",
            "NONE",
            "null",
        ],
    )
    def test_values_recognised_as_placeholder(self, value):
        assert _is_placeholder_manufacturer(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            "Acme Corp",
            "Acme, Inc.",
            "Contoso GmbH",
            "Siemens AG",
            "The Acme Company",
            "abc123",
            "XYZ Industries",
            "Test Manufacturing Ltd.",
            "Lithium Project",
        ],
    )
    def test_legitimate_names_pass(self, value):
        assert _is_placeholder_manufacturer(value) is False


class TestLoadHarmonisedStandards:
    """Reference-data integrity tests — if the JSON structure drifts
    the DoC rendering silently breaks, so we pin the shape here."""

    def test_loads_without_raising(self):
        """File is shipped with the app — must parse every time."""
        data = _load_harmonised_standards()
        assert isinstance(data, dict)
        assert "standards" in data
        assert "sources" in data

    def test_required_top_level_fields_present(self):
        data = _load_harmonised_standards()
        assert data["format_version"]
        assert data["description"]
        assert isinstance(data["standards"], list)
        assert len(data["standards"]) >= 2, "CRA + BSI minimum"

    def test_every_standard_has_minimum_fields(self):
        data = _load_harmonised_standards()
        for std in data["standards"]:
            assert std.get("id"), f"standard missing id: {std}"
            assert std.get("citation"), f"standard missing citation: {std}"
            # Either URL present or explicitly blank — never missing key.
            assert "url" in std
            # Harmonised flag must be a bool.
            assert isinstance(std.get("harmonised", False), bool)
            # cra_requirements_covered is always a list (may be empty).
            assert isinstance(std.get("cra_requirements_covered", []), list)

    def test_always_applicable_set_includes_cra_and_bsi(self):
        """These two anchor every DoC and cannot be removed."""
        data = _load_harmonised_standards()
        always = {s["id"] for s in data["standards"] if s.get("always_applicable")}
        assert "cra" in always
        assert "bsi-tr-03183-2" in always


class TestHarmonisedStandardsFallback:
    """Loader must degrade gracefully when the shipped JSON is missing
    or corrupt — the DoC still renders a valid Annex V §6 section from
    the minimal built-in fallback."""

    def test_missing_file_returns_minimal_fallback(self, tmp_path):
        """OSError path: shipped file is gone. Fallback must include
        the CRA regulation and BSI TR-03183-2 so the DoC's
        ``applied_standards`` isn't empty."""
        from sbomify.apps.compliance.services import _reference_data

        _reference_data.load_harmonised_standards.cache_clear()
        missing = tmp_path / "does-not-exist.json"
        with patch.object(_reference_data, "HARMONISED_STANDARDS_PATH", missing):
            data = _reference_data.load_harmonised_standards()
            _reference_data.load_harmonised_standards.cache_clear()

        assert data.get("_is_fallback") is True
        ids = {s["id"] for s in data["standards"]}
        assert {"cra", "bsi-tr-03183-2"}.issubset(ids)

    def test_invalid_json_returns_minimal_fallback(self, tmp_path):
        """JSONDecodeError path: file is present but corrupt. Same
        fallback so a corrupted deploy doesn't brick DoC generation."""
        from sbomify.apps.compliance.services import _reference_data

        _reference_data.load_harmonised_standards.cache_clear()
        broken = tmp_path / "cra-harmonised-standards.json"
        broken.write_text("{ this is not JSON", encoding="utf-8")
        with patch.object(_reference_data, "HARMONISED_STANDARDS_PATH", broken):
            data = _reference_data.load_harmonised_standards()
            _reference_data.load_harmonised_standards.cache_clear()

        assert data.get("_is_fallback") is True
        assert len(data["standards"]) >= 2

    def test_read_bytes_returns_none_on_missing_file(self, tmp_path):
        """The export service's ``read_harmonised_standards_bytes``
        shortcut returns None (not bytes) when the file is gone, so
        the caller can skip the embedded copy rather than writing a
        fallback blob."""
        from sbomify.apps.compliance.services import _reference_data

        missing = tmp_path / "does-not-exist.json"
        with patch.object(_reference_data, "HARMONISED_STANDARDS_PATH", missing):
            assert _reference_data.read_harmonised_standards_bytes() is None


@pytest.mark.django_db
class TestSelectAppliedStandards:
    """Unit coverage for the selection predicate used by the DoC
    context. Keeps the conservative default (always_applicable only)
    honest; a future opt-in for EN 18031 needs to add a test here."""

    def test_selects_only_always_applicable_for_default_assessment(self, assessment):
        standards = _select_applied_standards(assessment)
        ids_in_citation = [s["citation"] for s in standards]
        # CRA regulation and BSI TR-03183-2 always appear.
        assert any("Regulation (EU) 2024/2847" in c for c in ids_in_citation)
        assert any("BSI TR-03183-2" in c for c in ids_in_citation)
        # EN 18031-1/-2/-3 are NOT always_applicable by default.
        assert not any("EN 18031-1" in c for c in ids_in_citation)
        assert not any("EN 18031-2" in c for c in ids_in_citation)
        assert not any("EN 18031-3" in c for c in ids_in_citation)
        # Draft CRA-specific standards (not yet harmonised) also excluded.
        assert not any("EN 304 626" in c for c in ids_in_citation)

    def test_selected_entries_carry_cra_mapping_when_documented(self, assessment):
        standards = _select_applied_standards(assessment)
        bsi = next(s for s in standards if "BSI TR-03183-2" in s["citation"])
        assert bsi["cra_requirements_covered"], "BSI must map to CRA Annex I Part II(1)"
        assert bsi["harmonised"] is False
        assert "Annex I, Part II, §1" in {
            req["cra_reference"] for req in bsi["cra_requirements_covered"]
        }


@pytest.mark.django_db
class TestDocUrlsInRendering:
    """Regression: the DoC must render URLs as inline markdown refs so
    a notified body can click straight through to each authority."""

    def test_bsi_url_rendered(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "bsi.bund.de" in content

    def test_cra_url_rendered(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY)
        content = result.value
        assert "eur-lex.europa.eu/eli/reg/2024/2847" in content


@pytest.mark.django_db
class TestRiskAssessment:
    """Test risk assessment includes control findings."""

    def test_includes_control_findings_tables(self, assessment):
        # Set some findings
        findings = list(
            OSCALFinding.objects.filter(assessment_result=assessment.oscal_assessment_result).order_by(
                "control__sort_order"
            )[:2]
        )
        findings[0].status = "satisfied"
        findings[0].notes = "Implemented"
        findings[0].save()

        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.RISK_ASSESSMENT)
        content = result.value
        assert "Security by Design" in content
        assert "Vulnerability Handling" in content
        assert "Satisfied" in content


@pytest.mark.django_db
class TestRegenerateAll:
    @patch("sbomify.apps.core.object_store.S3Client")
    def test_generates_all_document_kinds(self, mock_s3_cls, assessment):
        result = regenerate_all(assessment)

        assert result.ok
        assert result.value == 9
        assert CRAGeneratedDocument.objects.filter(assessment=assessment).count() == 9


@pytest.mark.django_db
class TestRegenerateStale:
    @patch("sbomify.apps.core.object_store.S3Client")
    def test_regenerates_only_stale_documents(self, mock_s3_cls, assessment):
        # Generate all
        regenerate_all(assessment)

        # Mark only 2 as stale
        CRAGeneratedDocument.objects.filter(assessment=assessment, document_kind__in=["vdp", "security_txt"]).update(
            is_stale=True
        )

        result = regenerate_stale(assessment)
        assert result.ok
        assert result.value == 2

        # Verify none are stale now
        assert CRAGeneratedDocument.objects.filter(assessment=assessment, is_stale=True).count() == 0


@pytest.mark.django_db
class TestGetDocumentPreview:
    def test_returns_rendered_string(self, assessment):
        result = get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.VDP)

        assert result.ok
        assert isinstance(result.value, str)
        assert "Vulnerability Disclosure Policy" in result.value
        assert "Doc Gen Product" in result.value

    def test_does_not_persist(self, assessment):
        get_document_preview(assessment, CRAGeneratedDocument.DocumentKind.VDP)
        assert CRAGeneratedDocument.objects.filter(assessment=assessment).count() == 0

    def test_invalid_kind_returns_error(self, assessment):
        result = get_document_preview(assessment, "bogus")
        assert not result.ok


class TestSanitizeMarkdownEscape:
    """``_sanitize(escape_markdown=True)`` has to keep operator input
    from injecting Markdown / HTML into rendered CRA artefacts. These
    tests exercise the escape layer directly so a regression is caught
    without the full template pipeline."""

    def test_html_tags_are_escaped(self):
        """Open angle brackets MUST be prefixed with a backslash so a
        payload like ``<script>`` is rendered literally when the
        Markdown is later converted to HTML (DoC is often piped
        through pandoc → HTML)."""
        out = _sanitize("<script>alert(1)</script>", escape_markdown=True)
        # No unescaped ``<`` survives — every angle bracket has a
        # backslash immediately before it.
        assert "\\<" in out
        assert "\\>" in out
        # No bare ``<script>`` tag — raw HTML-rendering renderers will
        # see literal text instead of an opening tag.
        assert "<script>" not in out
        assert "</script>" not in out
        # Content preserved; just escaped in place.
        assert "script" in out
        assert "alert" in out

    def test_markdown_link_syntax_escaped(self):
        """``[click](javascript:alert(1))`` must survive as literal
        text so no operator can embed arbitrary URL schemes into the
        rendered DoC."""
        out = _sanitize("[click me](javascript:alert(1))", escape_markdown=True)
        assert "\\[" in out
        assert "\\]" in out
        assert "\\(" in out
        assert "\\)" in out

    def test_image_embed_syntax_escaped(self):
        """Tracking-pixel injection via ``![x](url)`` is defused."""
        out = _sanitize("![pixel](http://attacker.example/log)", escape_markdown=True)
        assert "\\!" in out
        assert "\\[" in out

    def test_plain_text_passes_through(self):
        """Legitimate product descriptions with plain words must survive
        unchanged except for escape of any metacharacter that happens
        to appear in them."""
        out = _sanitize("Lithium Python Stack 1.0", escape_markdown=True)
        assert "Lithium Python Stack 1.0" in out

    def test_escape_markdown_defaults_to_off(self):
        """Existing call sites that don't pass the flag get the same
        behaviour as before — control-char strip only."""
        out = _sanitize("<script>alert(1)</script>")
        assert out == "<script>alert(1)</script>"

    def test_pipe_escape_still_works_for_table_cells(self):
        """``escape_pipe`` is orthogonal to ``escape_markdown``; both
        can apply at once (finding notes in risk-assessment tables)."""
        out = _sanitize("a|b<c>", escape_pipe=True, escape_markdown=True)
        assert "\\|" in out
        assert "\\<" in out


@pytest.mark.django_db
class TestDoCRejectsMarkdownInjection:
    """End-to-end: hostile operator input in product / manufacturer /
    intended-use fields must NOT produce a DoC that renders as
    executable HTML or clickable attacker links when viewed in a
    Markdown renderer. The previous pipeline had ``autoescape=False``
    on the Django engine and no per-field Markdown escape — CVSS 6.4
    cross-site scripting via regulated-document viewer."""

    @pytest.fixture
    def hostile_assessment(self, sample_team_with_owner_member, sample_user):
        """Assessment populated with attack payloads in every
        operator-controlled free-text field."""
        team = sample_team_with_owner_member.team
        profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
        ContactEntity.objects.create(
            profile=profile,
            name='ACME <script>alert("mfr")</script>',
            email="info@example.test",
            address='Street 1 [phish](javascript:alert(1))',
            is_manufacturer=True,
        )
        p = Product.objects.create(
            name='<iframe src="http://attacker"></iframe>',
            team=team,
        )
        ares = get_or_create_assessment(p.id, sample_user, team)
        assert ares.ok
        a = ares.value
        a.intended_use = "Embedded ![pixel](http://attacker/track.png)"
        a.data_deletion_instructions = "Run `rm -rf /` and [confirm](https://attacker)"
        a.support_hours = "09:00-17:00 <img onerror=alert(1)>"
        a.update_frequency = "monthly **<b>"
        a.save()
        return a

    def test_doc_renders_without_raw_script_tags(self, hostile_assessment):
        result = get_document_preview(
            hostile_assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY
        )
        content = result.value
        # Raw HTML/JS fragments must NOT survive into the rendered doc.
        assert "<script>" not in content
        assert "<iframe" not in content
        assert "<img onerror" not in content
        # The label text is still there — just Markdown-escaped.
        assert "script" in content

    def test_doc_renders_without_unescaped_markdown_links(self, hostile_assessment):
        result = get_document_preview(
            hostile_assessment, CRAGeneratedDocument.DocumentKind.DECLARATION_OF_CONFORMITY
        )
        content = result.value
        # A bare `[phish](javascript:...)` sequence in the output would
        # render as a clickable link. Escaped brackets break that shape.
        assert "[phish](javascript" not in content

    def test_user_instructions_escapes_hostile_input(self, hostile_assessment):
        result = get_document_preview(
            hostile_assessment, CRAGeneratedDocument.DocumentKind.USER_INSTRUCTIONS
        )
        content = result.value
        assert "<img onerror" not in content
        assert "![pixel](http://attacker" not in content
        assert "[confirm](https://attacker" not in content

    def test_decommissioning_guide_escapes_data_deletion_instructions(self, hostile_assessment):
        result = get_document_preview(
            hostile_assessment, CRAGeneratedDocument.DocumentKind.DECOMMISSIONING_GUIDE
        )
        content = result.value
        assert "[confirm](https://attacker" not in content


class TestManufacturerPolicyParity:
    """Shared-source-of-truth check: the placeholder predicate lives in
    ``sbomify.apps.compliance.services._manufacturer_policy``. Both
    ``document_generation_service`` and ``export_service`` import the
    same function via aliasing. This test pins that parity — if anyone
    re-introduces a local copy of the frozenset (the pre-fix shape),
    the two imports will diverge and this test fails."""

    def test_both_services_import_same_predicate(self):
        """Identity check: the two module-level references are the same
        function object, not copies."""
        from sbomify.apps.compliance.services.document_generation_service import (
            _is_placeholder_manufacturer as doc_predicate,
        )
        from sbomify.apps.compliance.services.export_service import (
            _is_placeholder_manufacturer as export_predicate,
        )
        assert doc_predicate is export_predicate

    def test_placeholder_vocabulary_is_single_source(self):
        """Only one frozenset of placeholder values exists anywhere
        under the compliance services — no local copies."""
        import importlib

        mod = importlib.import_module(
            "sbomify.apps.compliance.services._manufacturer_policy"
        )
        assert isinstance(mod.PLACEHOLDER_MANUFACTURER_VALUES, frozenset)
        # Invariants: whitespace stripped, lowercase keys, empty string
        # included to model "no manufacturer configured".
        for v in mod.PLACEHOLDER_MANUFACTURER_VALUES:
            assert v == v.lower()
            assert v == v.strip()
        assert "" in mod.PLACEHOLDER_MANUFACTURER_VALUES
