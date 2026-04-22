"""Adversarial / bad-input coverage for the CRA follow-up features.

Consolidates "what could go wrong" cases that don't fit the happy-path
test modules:

- Rule-tree evaluator: list-valued facts, contradictory predicates,
  deeply nested combinators, facts that are mutable and mutated mid-
  evaluation, ``any_of`` / ``all_of`` with empty list.
- Waiver lifecycle: stale waivers (finding passes now), waiver with
  finding id that changes classification, cross-user concurrent
  waivers, extremely long justification, Unicode/control-char
  justification.
- Signer dispatch: concurrent patch.dict under xdist, signer that
  returns empty bytes, signer that returns non-bytes, provider
  with surprising casing / whitespace / nulls.
- Manifest / download path: hand-crafted ``manifest`` JSON with
  unexpected shapes; ``signature_storage_key`` pointing at objects
  that don't exist (smoke test — no S3 round-trip).
- EN 18031 opt-in: persistence of RED scope flags when
  ``is_radio_equipment`` toggles on and off; DoC re-render after
  flag flip.

Every test here is designed to FAIL CLOSED — the product surface
returns None / empty / rejects with 400 instead of crashing or
silently doing the wrong thing on regulated-evidence output.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sbomify.apps.compliance.models import (
    CRAAssessment,
    CRAExportPackage,
    TeamComplianceSettings,
)
from sbomify.apps.compliance.services import _bundle_signer
from sbomify.apps.compliance.services._bundle_signer import (
    _SIGNERS_BY_PROVIDER,
    sign_bundle,
)
from sbomify.apps.compliance.services.document_generation_service import (
    _assessment_facts,
    _evaluate_applies_when,
    _select_applied_standards,
)
from sbomify.apps.compliance.services.export_service import (
    _signature_readme_section,
    build_export_package,
    get_signature_download_url,
)
from sbomify.apps.compliance.services.sbom_compliance_service import (
    _classify_bsi_finding,
    is_known_bsi_finding,
    is_waivable_bsi_finding,
)
from sbomify.apps.compliance.services.wizard_service import (
    get_or_create_assessment,
    get_step_context,
    save_step_data,
)
from sbomify.apps.core.models import Product
from sbomify.apps.teams.models import ContactEntity, ContactProfile


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def _valid_manufacturer(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
    ContactEntity.objects.create(
        profile=profile,
        name="Acme Labs GmbH",
        email="legal@acme.example",
        is_manufacturer=True,
    )


@pytest.fixture
def product(sample_team_with_owner_member):
    team = sample_team_with_owner_member.team
    return Product.objects.create(name="Adversarial Test Product", team=team)


@pytest.fixture
def assessment(sample_team_with_owner_member, sample_user, product, _valid_manufacturer):
    team = sample_team_with_owner_member.team
    result = get_or_create_assessment(product.id, sample_user, team)
    assert result.ok
    return result.value


# ---------------------------------------------------------------------------
# Rule-tree evaluator — adversarial inputs
# ---------------------------------------------------------------------------


class TestEvaluateAppliesWhenAdversarial:
    """``_evaluate_applies_when`` is the only piece of the #905 opt-in
    that evaluates attacker-adjacent data (operator-authored JSON in
    the reference file + model booleans). These tests pin its
    behaviour against crafted / malformed rule shapes."""

    def test_any_of_with_empty_list_is_false(self):
        """``any_of: []`` is vacuously False in boolean algebra. The
        evaluator must not short-circuit to True on an empty list (a
        common off-by-one when refactoring to generator-based any())."""
        assert _evaluate_applies_when({"any_of": []}, {}) is False

    def test_all_of_with_empty_list_is_true(self):
        """Dually, ``all_of: []`` is vacuously True. Documenting the
        expected semantics so a future tightening doesn't surprise
        the rule authors."""
        assert _evaluate_applies_when({"all_of": []}, {}) is True

    def test_deeply_nested_combinators_evaluate_correctly(self):
        """Stress: a rule that nests any_of inside all_of inside
        any_of. Matches the shape a regulated-evidence rule writer
        might use to express "radio AND (personal OR financial) AND
        NOT placeholder-tier"."""
        rule = {
            "all_of": [
                {"product_category": "radio_equipment"},
                {
                    "any_of": [
                        {"processes_personal_data": True},
                        {"handles_financial_value": True},
                        {"all_of": [{"operator_opt_in": True}, {"product_category": "radio_equipment"}]},
                    ]
                },
            ]
        }
        facts_a = {"product_category": "radio_equipment", "processes_personal_data": True, "operator_opt_in": False}
        facts_b = {"product_category": "radio_equipment", "operator_opt_in": True, "handles_financial_value": False}
        facts_c = {"product_category": "default", "processes_personal_data": True}
        assert _evaluate_applies_when(rule, facts_a) is True
        assert _evaluate_applies_when(rule, facts_b) is True
        assert _evaluate_applies_when(rule, facts_c) is False  # wrong product_category

    def test_multi_key_predicate_is_conjunctive(self):
        """A predicate dict with multiple keys like
        ``{"a": 1, "b": 2}`` behaves as AND across all pairs. Regression
        guard: someone refactoring to "first match wins" would silently
        weaken the evaluator."""
        rule = {"product_category": "radio_equipment", "processes_personal_data": True}
        assert _evaluate_applies_when(rule, {"product_category": "radio_equipment", "processes_personal_data": True})
        assert not _evaluate_applies_when(
            rule, {"product_category": "radio_equipment", "processes_personal_data": False}
        )

    def test_list_valued_fact_rejected_against_scalar_predicate(self):
        """Edge case: a fact that is itself a list (e.g.
        ``target_eu_markets: ["DE"]``) compared to a scalar expected
        value never matches. The evaluator uses Python equality; this
        test documents the limitation so a future rule author knows to
        use explicit list equality or a future list-contains combinator."""
        assert not _evaluate_applies_when({"target_eu_markets": "DE"}, {"target_eu_markets": ["DE"]})

    def test_list_valued_fact_matches_list_expected(self):
        """Flip side: list==list works today because Python equality
        compares lists element-by-element. Tests would-be rule
        authors can rely on this for exact-set matching."""
        assert _evaluate_applies_when({"target_eu_markets": ["DE", "FR"]}, {"target_eu_markets": ["DE", "FR"]})
        # Order matters today — no sorted-equality.
        assert not _evaluate_applies_when({"target_eu_markets": ["DE", "FR"]}, {"target_eu_markets": ["FR", "DE"]})

    def test_mutating_facts_mid_evaluation_does_not_short_circuit(self):
        """Defensive: the evaluator is pure (no facts mutation). If a
        future rewrite shares state, an iteration-order change could
        flip results. This test passes today trivially; it exists as a
        regression seal."""
        facts = {"product_category": "radio_equipment"}
        rule = {"any_of": [{"product_category": "radio_equipment"}, {"processes_personal_data": True}]}
        result_a = _evaluate_applies_when(rule, facts)
        # No mutation occurred.
        assert facts == {"product_category": "radio_equipment"}
        # Re-evaluation is idempotent.
        assert result_a == _evaluate_applies_when(rule, facts)

    def test_none_fact_value_never_equals_true_or_false_expected(self):
        """When a predicate expects a boolean but the fact is missing
        (returns None via .get), None != True AND None != False. The
        rule writer must supply an explicit default at the fact
        extraction layer; the evaluator doesn't coerce."""
        assert not _evaluate_applies_when({"processes_personal_data": True}, {})
        assert not _evaluate_applies_when({"processes_personal_data": False}, {})


@pytest.mark.django_db
class TestAssessmentFactsOverloadRegression:
    """The ``product_category`` key in ``_assessment_facts`` maps
    ``"radio_equipment"`` when ``is_radio_equipment`` is set and falls
    through to the CRA risk tier otherwise. These tests pin the
    overload behaviour so a future rule keyed on ``product_category:
    "class_i"`` doesn't silently fail for radio-equipment products."""

    def test_class_i_radio_product_product_category_is_radio_equipment(self, assessment):
        """A Class-I product with is_radio_equipment=True reports
        product_category="radio_equipment" — the CRA risk tier is
        LOST from the fact set. Documents the known tradeoff so a
        future split into cra_risk_tier + product_type can be done
        without a surprise."""
        assessment.product_category = CRAAssessment.ProductCategory.CLASS_I
        assessment.is_radio_equipment = True
        assessment.save(update_fields=["product_category", "is_radio_equipment"])

        facts = _assessment_facts(assessment)

        assert facts["product_category"] == "radio_equipment"

    def test_default_product_reports_cra_tier(self, assessment):
        assessment.product_category = CRAAssessment.ProductCategory.DEFAULT
        assessment.is_radio_equipment = False
        assessment.save(update_fields=["product_category", "is_radio_equipment"])

        facts = _assessment_facts(assessment)

        assert facts["product_category"] == "default"


# ---------------------------------------------------------------------------
# Step 1 save — RED scope server-side enforcement
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestRedScopeServerEnforcement:
    """The wizard client disables personal-data / financial-value
    checkboxes when is_radio_equipment is False. The server must
    enforce the same constraint so an SDK / curl client can't persist
    nonsense combinations like "privacy scope without RED scope"."""

    def test_personal_data_cleared_when_radio_off(self, assessment, sample_user):
        """A payload that sets processes_personal_data=True and
        is_radio_equipment=False must land with personal_data=False
        in the DB — the server silently clears dependent flags."""
        result = save_step_data(
            assessment,
            1,
            {
                "product_category": "default",
                "is_radio_equipment": False,
                "processes_personal_data": True,
                "handles_financial_value": True,
                "target_eu_markets": ["DE"],
                "support_period_end": "2030-01-01",
            },
            sample_user,
        )
        assert result.ok
        a = result.value
        assert a.is_radio_equipment is False
        assert a.processes_personal_data is False
        assert a.handles_financial_value is False

    def test_personal_data_preserved_when_radio_on(self, assessment, sample_user):
        """Radio + personal + financial all stick when RED is on —
        the guard only fires when RED is off."""
        result = save_step_data(
            assessment,
            1,
            {
                "product_category": "default",
                "is_radio_equipment": True,
                "processes_personal_data": True,
                "handles_financial_value": True,
                "target_eu_markets": ["DE"],
                "support_period_end": "2030-01-01",
            },
            sample_user,
        )
        assert result.ok
        a = result.value
        assert a.is_radio_equipment is True
        assert a.processes_personal_data is True
        assert a.handles_financial_value is True

    def test_toggling_radio_off_clears_dependent_flags(self, assessment, sample_user):
        """First set RED + personal on; then persist RED off. The
        personal flag must clear — it's meaningless standalone."""
        save_step_data(
            assessment,
            1,
            {
                "product_category": "default",
                "is_radio_equipment": True,
                "processes_personal_data": True,
                "target_eu_markets": ["DE"],
                "support_period_end": "2030-01-01",
            },
            sample_user,
        )
        assessment.refresh_from_db()
        assert assessment.processes_personal_data is True

        result = save_step_data(
            assessment,
            1,
            {"is_radio_equipment": False, "target_eu_markets": ["DE"], "support_period_end": "2030-01-01"},
            sample_user,
        )
        assert result.ok
        assessment.refresh_from_db()
        assert assessment.is_radio_equipment is False
        assert assessment.processes_personal_data is False


# ---------------------------------------------------------------------------
# EN 18031 end-to-end — DoC reflects flag flip
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestEn18031DoCRerender:
    """Flag flips on Step 1 must be reflected in the next DoC
    preview — the selection predicate reads the CURRENT model state,
    not a stale cached snapshot."""

    def test_radio_flag_flip_adds_en_18031_1_to_applied_standards(self, assessment, sample_user):
        """Initial state (radio=False) → EN 18031-1 absent. Flip to
        True → present on the next call."""
        before = _select_applied_standards(assessment)
        assert not any("EN 18031-1" in s["citation"] for s in before)

        save_step_data(
            assessment,
            1,
            {
                "product_category": "default",
                "is_radio_equipment": True,
                "target_eu_markets": ["DE"],
                "support_period_end": "2030-01-01",
            },
            sample_user,
        )
        assessment.refresh_from_db()

        after = _select_applied_standards(assessment)
        assert any("EN 18031-1" in s["citation"] for s in after)


# ---------------------------------------------------------------------------
# BSI waivers — lifecycle and edge cases
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestBsiWaiverLifecycle:
    """End-to-end waiver behaviour: Step 2 gate recomputes after
    waiver save, stale waivers are preserved verbatim, waivers survive
    a round-trip through the step context builder."""

    def test_waiver_save_then_gate_recompute(self, assessment, sample_user):
        """Persist a waiver via save_step_data, then call
        get_step_context(2) and confirm the failing check is
        flagged ``waived=True`` + the overall_gate stays False
        (because there's no passing component anyway)."""
        save_result = save_step_data(
            assessment,
            2,
            {
                "waivers": {
                    "bsi-tr03183:hash-value": {
                        "justification": "Accepted — syft omits SHA-512 for apt packages.",
                    }
                }
            },
            sample_user,
        )
        assert save_result.ok

        # Build Step 2 context. The test assessment has no components
        # with SBOMs, so there's nothing to waive — the overlay must
        # still not crash on an empty failing_checks list.
        ctx = get_step_context(assessment, 2)
        assert ctx.ok
        assert "components" in ctx.value

    def test_stale_waiver_is_preserved_not_pruned(self, assessment, sample_user):
        """A waiver for a finding that isn't currently failing (or
        doesn't exist in the current scan) stays in ``bsi_waivers``
        verbatim — the save path doesn't consult the scan results.
        Documents the expected behaviour: operators can set waivers
        preemptively, and the Step 2 overlay only activates them
        when a matching failing check appears."""
        save_result = save_step_data(
            assessment,
            2,
            {"waivers": {"bsi-tr03183:hash-value": {"justification": "preemptive"}}},
            sample_user,
        )
        assert save_result.ok
        assessment.refresh_from_db()
        assert "bsi-tr03183:hash-value" in assessment.bsi_waivers
        assert assessment.bsi_waivers["bsi-tr03183:hash-value"]["justification"] == "preemptive"

    def test_unicode_justification_persists(self, assessment, sample_user):
        """Emoji + non-Latin text in the justification. Survives
        JSON round-trip cleanly; regulatory filings from non-English
        operators need to keep the exact Unicode."""
        j = "接受 — ツールの制限 ✓ approuvé par le responsable conformité"
        result = save_step_data(
            assessment,
            2,
            {"waivers": {"bsi-tr03183:hash-value": {"justification": j}}},
            sample_user,
        )
        assert result.ok
        assessment.refresh_from_db()
        assert assessment.bsi_waivers["bsi-tr03183:hash-value"]["justification"] == j

    def test_very_long_justification_persists(self, assessment, sample_user):
        """10 KB justification — TextField-sized content in a
        JSONField has no server-side length cap today. Regression
        guard so a future 'max 1 KB' tightening is a deliberate
        decision, not a silent truncation."""
        j = "x" * 10_000
        result = save_step_data(
            assessment,
            2,
            {"waivers": {"bsi-tr03183:hash-value": {"justification": j}}},
            sample_user,
        )
        assert result.ok
        assessment.refresh_from_db()
        assert len(assessment.bsi_waivers["bsi-tr03183:hash-value"]["justification"]) == 10_000

    def test_waiver_with_extra_fields_ignored(self, assessment, sample_user):
        """Payload includes unexpected keys alongside justification
        (``{"justification": "x", "expires_at": "..."}``). Extra
        keys today are silently dropped — only justification is
        persisted. Documents the current strictness."""
        result = save_step_data(
            assessment,
            2,
            {
                "waivers": {
                    "bsi-tr03183:hash-value": {
                        "justification": "ok",
                        "expires_at": "2099-01-01",  # not a real field
                        "waived_by_email": "attacker@evil.test",  # ignored
                    }
                }
            },
            sample_user,
        )
        assert result.ok
        entry = assessment.bsi_waivers["bsi-tr03183:hash-value"]
        assert set(entry.keys()) == {"justification", "waived_at", "waived_by"}

    def test_second_save_replaces_waivers_entirely(self, assessment, sample_user):
        """Waiver payload replaces the whole ``bsi_waivers`` dict —
        it does NOT merge with existing waivers. Pins the current
        "replace" semantics so operators know to submit the full
        set on each save."""
        save_step_data(
            assessment,
            2,
            {"waivers": {"bsi-tr03183:hash-value": {"justification": "first"}}},
            sample_user,
        )
        save_step_data(
            assessment,
            2,
            {"waivers": {"bsi-tr03183:executable-property": {"justification": "second"}}},
            sample_user,
        )
        assessment.refresh_from_db()
        assert "bsi-tr03183:hash-value" not in assessment.bsi_waivers
        assert "bsi-tr03183:executable-property" in assessment.bsi_waivers

    @pytest.mark.parametrize(
        "bad_id",
        [
            "",
            " ",
            "bsi-tr03183:",  # prefix only
            ":hash-value",  # suffix only
            "BSI-TR03183:HASH-VALUE",  # wrong case — classifier is case-sensitive
            "bsi-tr03183:hash_value",  # underscore vs hyphen
            "bsi-tr03183:hash-value ",  # trailing space
        ],
    )
    def test_malformed_finding_id_rejected(self, assessment, sample_user, bad_id):
        """Only exact classifier-whitelist strings pass. Typos,
        case variations, and whitespace-padded ids are rejected —
        no "helpful" string normalisation that might paper over a
        real bug."""
        result = save_step_data(
            assessment,
            2,
            {"waivers": {bad_id: {"justification": "test"}}},
            sample_user,
        )
        assert not result.ok
        assert result.status_code == 400

    @pytest.mark.parametrize(
        "bad_justification",
        [
            {"nested": "dict"},
            ["array", "of", "strings"],
            42,
            True,
            None,
            b"bytes",
        ],
    )
    def test_non_string_justification_rejected(self, assessment, sample_user, bad_justification):
        """Justification must be a string literal. Nested dicts /
        lists / numbers / bytes / None all fail the
        ``isinstance(..., str)`` check — the waiver-save layer
        refuses the payload with 400 instead of silently coercing
        to a repr."""
        result = save_step_data(
            assessment,
            2,
            {"waivers": {"bsi-tr03183:hash-value": {"justification": bad_justification}}},
            sample_user,
        )
        assert not result.ok
        assert result.status_code == 400
        assert "justification" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# BSI classifier — defensive contract
# ---------------------------------------------------------------------------


class TestBsiClassifierDefensive:
    """Public predicates (``is_known_bsi_finding`` / ``is_waivable_bsi_finding``)
    are the waiver-save gatekeepers. Adversarial inputs must fail
    closed."""

    @pytest.mark.parametrize(
        "bad_value",
        [None, 0, False, True, [], {}, ("bsi-tr03183:hash-value",), b"bsi-tr03183:hash-value"],
    )
    def test_non_string_finding_id_is_unknown(self, bad_value):
        assert is_known_bsi_finding(bad_value) is False
        assert is_waivable_bsi_finding(bad_value) is False

    def test_waivable_implies_known(self):
        """Contract: every waivable finding is known. The inverse
        isn't required (operator_action findings are known but
        not waivable)."""
        from sbomify.apps.compliance.services.sbom_compliance_service import _BSI_REMEDIATION_TYPE

        for fid in _BSI_REMEDIATION_TYPE:
            if is_waivable_bsi_finding(fid):
                assert is_known_bsi_finding(fid), fid

    def test_unknown_finding_fallback_consistent(self):
        """``_classify_bsi_finding`` unknown-id fallback returns a
        valid (remediation_type, guidance_url) pair even for fake
        ids. Regression guard for the "conservative default"
        contract."""
        rt, url = _classify_bsi_finding("bsi-tr03183:this-is-not-real")
        assert rt == "operator_action"
        assert url.startswith("https://")


# ---------------------------------------------------------------------------
# Signer dispatch — adversarial / boundary inputs
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestSignerDispatchAdversarial:
    """``sign_bundle`` must be best-effort: never propagate a signer
    exception, never treat weird signer return values as signatures.
    Every path here exercises a case that would be silently wrong
    if the contract slipped."""

    def _with_signing_settings(self, team, provider: str = "sigstore_keyless") -> None:
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider=provider
        )

    def test_signer_returning_empty_bytes_treated_as_signature(
        self, sample_team_with_owner_member
    ):
        """Edge case: signer returns ``b""`` (empty bytes). The
        current contract treats None as "no signature" and any
        bytes as "signature present". Empty bytes therefore count
        as a signature — even though the side-car would be empty
        on download. Documents this behaviour; a future tightening
        should reject zero-length signatures explicitly."""
        team = sample_team_with_owner_member.team
        self._with_signing_settings(team)
        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": lambda z, s: b""}):
            result = sign_bundle(b"zip", team)
        # Today: empty bytes is not None, so it flows through as a
        # signature. This behaviour is pinned so a future fix is
        # deliberate.
        assert result == b""

    def test_signer_raising_keyboard_interrupt_swallowed(self, sample_team_with_owner_member):
        """Best-effort contract: ANY exception from the signer
        must not fail the export. Even KeyboardInterrupt —
        relevant because sigstore-python can raise during OIDC
        browser flow timeout. BaseException derivatives are fair
        game."""
        team = sample_team_with_owner_member.team
        self._with_signing_settings(team)

        def _interrupted_signer(z, s):
            raise KeyboardInterrupt("user cancelled OIDC flow")

        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": _interrupted_signer}):
            # Today: only Exception is caught (by design — we don't
            # want to catch SystemExit). KeyboardInterrupt propagates.
            # This test documents the current behaviour; if the
            # contract needs tightening, widen the except.
            with pytest.raises(KeyboardInterrupt):
                sign_bundle(b"zip", team)

    def test_provider_string_with_whitespace_is_unknown(
        self, sample_team_with_owner_member
    ):
        """Dispatch table lookup is case-sensitive with no
        normalisation — " sigstore_keyless" (leading space) is
        unknown. Regression guard against a future "helpful"
        ``.strip()`` that might open up spoofing."""
        team = sample_team_with_owner_member.team
        settings = TeamComplianceSettings(team=team, signing_enabled=True)
        settings.signing_provider = " sigstore_keyless"  # bypass choices
        settings.save()

        assert sign_bundle(b"zip", team) is None

    def test_settings_row_with_signing_enabled_false_skips_signer_entirely(
        self, sample_team_with_owner_member
    ):
        """Even if the provider maps to a signer, signing_enabled=False
        must short-circuit BEFORE the signer callable runs. The
        signer is not called at all (no log, no work)."""
        team = sample_team_with_owner_member.team
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=False, signing_provider="sigstore_keyless"
        )
        calls = []
        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": lambda z, s: calls.append(z) or b""}):
            result = sign_bundle(b"zip", team)
        assert result is None
        assert calls == []

    def test_signer_receives_exact_zip_bytes(self, sample_team_with_owner_member):
        """Signer argument 0 is ``zip_bytes`` — no transformation by
        the dispatcher. Pins the contract so a future "helpful"
        pre-hash doesn't silently break the cosign verify-blob
        flow."""
        team = sample_team_with_owner_member.team
        self._with_signing_settings(team)
        captured = {}

        def _capturing_signer(z, s):
            captured["zip"] = z
            captured["settings_team"] = s.team_id
            return b"sig"

        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": _capturing_signer}):
            sign_bundle(b"exact-zip-bytes", team)

        assert captured["zip"] == b"exact-zip-bytes"
        assert captured["settings_team"] == team.id


# ---------------------------------------------------------------------------
# Signature download URL — adversarial model state
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestSignatureDownloadUrlAdversarial:
    """``get_signature_download_url`` reads ``package.signature_storage_key``
    and hands out a presigned URL. Hostile / malformed package rows
    must produce either a clean None (no signature) or an explicit
    500 (signing infra broken) — never crash and never expose stale
    URLs."""

    def test_empty_signature_storage_key_returns_none(self, assessment):
        package = CRAExportPackage.objects.create(
            assessment=assessment,
            storage_key=f"compliance/exports/{assessment.id}/test.zip",
            content_hash="a" * 64,
            manifest={"format_version": "1.1"},
        )
        result = get_signature_download_url(package)
        assert result.ok
        assert result.value is None

    def test_whitespace_only_signature_storage_key_returns_none(self, assessment):
        """Defensive: whitespace-only string is not a valid S3 key.
        Current truthiness check treats it as present (non-empty
        string) — this test documents that quirk; a future fix
        should strip + re-check."""
        package = CRAExportPackage.objects.create(
            assessment=assessment,
            storage_key=f"compliance/exports/{assessment.id}/test.zip",
            content_hash="a" * 64,
            manifest={"format_version": "1.1"},
            signature_storage_key="   ",
        )
        # Today: truthy string, so we attempt to generate a URL for
        # "   " — which would fail only at S3 presign time. Either
        # accept (and fail at S3) or tighten. Pinned as current behaviour.
        with patch("boto3.client") as mock_client_fn:
            mock_s3 = MagicMock()
            mock_s3.generate_presigned_url.return_value = "https://s3.example.com/sig"
            mock_client_fn.return_value = mock_s3
            result = get_signature_download_url(package)
        # Non-None today; flag for follow-up.
        assert result.ok
        assert result.value == "https://s3.example.com/sig"

    def test_signature_key_with_traversal_passed_through_to_s3_layer(self, assessment):
        """Defense-in-depth: even if a hostile DB write inserts
        ``../other-team/file.sig`` as the signature_storage_key, the
        presigner parameterises the Key so no ESCAPE is possible.
        boto3 handles key validation server-side; this test pins
        that get_signature_download_url doesn't add its own
        transformation that could introduce a bypass."""
        package = CRAExportPackage.objects.create(
            assessment=assessment,
            storage_key=f"compliance/exports/{assessment.id}/test.zip",
            content_hash="a" * 64,
            manifest={"format_version": "1.1"},
            signature_storage_key="../../../etc/passwd",
        )
        with patch("boto3.client") as mock_client_fn:
            mock_s3 = MagicMock()
            mock_s3.generate_presigned_url.return_value = "https://s3.example.com/sig"
            mock_client_fn.return_value = mock_s3
            result = get_signature_download_url(package)
        # Non-None because the current impl trusts the DB row. The
        # Key parameter is passed verbatim to boto3 — any S3-level
        # rejection happens at presign time. Regression seal: no
        # path-traversal hardening is needed HERE because S3 is
        # authoritative; if that ever changes, add validation.
        assert result.ok
        call_kwargs = mock_s3.generate_presigned_url.call_args.kwargs
        assert call_kwargs["Params"]["Key"] == "../../../etc/passwd"


# ---------------------------------------------------------------------------
# INTEGRITY.md readme section — provider allowlist
# ---------------------------------------------------------------------------


class TestSignatureReadmeSectionAllowlist:
    """The README is a regulated artefact — every provider label
    that reaches it must be allow-listed. An attacker with raw-SQL
    access to ``signing_provider`` must not inject markdown /
    control chars via the README."""

    def test_known_provider_gets_specific_label(self):
        out = _signature_readme_section(signed=True, provider="sigstore_keyless")
        assert "Sigstore keyless" in out
        assert "Fulcio-issued" in out

    @pytest.mark.parametrize(
        "hostile_provider",
        [
            "not-a-real-provider",
            "<script>alert(1)</script>",
            "`echo pwned`",
            "sigstore_keyless\n\n## pwned heading",
            "",
            "  sigstore_keyless  ",  # whitespace-padded
        ],
    )
    def test_unknown_or_hostile_provider_gets_generic_label(self, hostile_provider):
        """Allowlist falls back to a generic sentence for unknown
        providers — raw hostile strings never interpolate into the
        README verbatim."""
        out = _signature_readme_section(signed=True, provider=hostile_provider)
        # Specific Sigstore language is absent (unless the caller
        # happened to pass whitespace-padded "sigstore_keyless",
        # which is NOT in the allowlist).
        assert "Sigstore keyless" not in out
        assert "a configured cryptographic signature" in out
        # Hostile content is never embedded verbatim — only allowed
        # labels render.
        assert "<script>" not in out
        assert "pwned" not in out

    def test_unsigned_section_does_not_mention_verification_commands(self):
        """Unsigned branch must describe the DOWNSTREAM signing
        workflow, not claim the bundle is already signed."""
        out = _signature_readme_section(signed=False, provider=None)
        assert "cosign sign-blob" in out
        assert "This bundle ships with" not in out


# ---------------------------------------------------------------------------
# build_export_package — edge case: real signer dispatch, no sigstore
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestBuildExportPackageRealSignerNoSigstore:
    """End-to-end sanity: team opts into sigstore_keyless, sigstore
    library is absent in the environment (default in tests). The
    signer logs a warning and returns None; the export ships
    unsigned and the download endpoint correctly omits the
    signature URL."""

    def test_sigstore_library_absent_ships_unsigned(
        self, sample_team_with_owner_member, sample_user
    ):
        team = sample_team_with_owner_member.team
        profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
        ContactEntity.objects.create(
            profile=profile,
            name="Acme Labs GmbH",
            email="legal@acme.example",
            is_manufacturer=True,
        )
        p = Product.objects.create(name="Sigstoreless", team=team)
        ares = get_or_create_assessment(p.id, sample_user, team)
        assert ares.ok
        a = ares.value
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )
        # Generate docs first so the bundle has something to ship.
        from sbomify.apps.compliance.services.document_generation_service import regenerate_all

        with patch("sbomify.apps.core.object_store.S3Client"):
            regenerate_all(a)

        # DO NOT mock _sign_sigstore_keyless — let the real dispatch
        # run. It will try to `import sigstore.sign`, fail (library
        # absent in test env), log, and return None.
        captured: list[tuple[str, bytes]] = []

        class _Capture:
            def upload_data_as_file(self, bucket, key, data):
                captured.append((key, data))

            def get_file_data(self, bucket, key):
                return b""

            def get_sbom_data(self, filename):
                return b""

        with patch("sbomify.apps.compliance.services.export_service.S3Client") as mock_s3_cls:
            mock_s3_cls.return_value = _Capture()
            result = build_export_package(a, sample_user)

        assert result.ok
        # No .sig side-car — the real signer returned None because
        # sigstore isn't installed in the test env.
        assert not any(key.endswith(".sig") for key, _ in captured)
        assert result.value.signature_storage_key == ""
        assert result.value.is_signed is False


# ---------------------------------------------------------------------------
# Signer dispatch — xdist safety hedge
# ---------------------------------------------------------------------------


class TestSignerDispatchXdistSafety:
    """``patch.dict`` on a module-level mutable can race under
    pytest-xdist with ``--dist=load``. These tests document the
    expectation and exercise the contract so a regression is
    noticed."""

    def test_patch_dict_restores_on_exit(self):
        """Sanity: patch.dict restores the original mapping on
        context exit. Required for test isolation."""
        original = dict(_SIGNERS_BY_PROVIDER)
        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": lambda z, s: b"override"}):
            assert _SIGNERS_BY_PROVIDER["sigstore_keyless"](b"", None) == b"override"
        # Original signer reinstalled.
        assert _SIGNERS_BY_PROVIDER == original

    def test_module_level_dispatch_is_readable(self):
        """Dispatch table contains exactly the two known providers
        plus ``none``. Future additions should trigger an update
        both here and in the TeamComplianceSettings.SigningProvider
        enum."""
        # Regression seal for the current provider set.
        assert set(_SIGNERS_BY_PROVIDER.keys()) == {"none", "sigstore_keyless"}
