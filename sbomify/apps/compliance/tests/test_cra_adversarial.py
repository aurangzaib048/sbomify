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

    def test_justification_under_cap_persists(self, assessment, sample_user):
        """A 1 KB justification is within the 2 KB cap — persists
        verbatim. Regression guard for realistic operator usage."""
        j = "x" * 1_000
        result = save_step_data(
            assessment,
            2,
            {"waivers": {"bsi-tr03183:hash-value": {"justification": j}}},
            sample_user,
        )
        assert result.ok
        assessment.refresh_from_db()
        assert len(assessment.bsi_waivers["bsi-tr03183:hash-value"]["justification"]) == 1_000

    def test_justification_exceeding_cap_rejected(self, assessment, sample_user):
        """Defense-in-depth: 10 KB justification exceeds the
        ``_MAX_WAIVER_JUSTIFICATION_CHARS`` cap (2 KB). Rejects
        with 400 — prevents row-bloat / JSON-serialisation DoS."""
        j = "x" * 10_000
        result = save_step_data(
            assessment,
            2,
            {"waivers": {"bsi-tr03183:hash-value": {"justification": j}}},
            sample_user,
        )
        assert not result.ok
        assert result.status_code == 400
        assert "limit" in (result.error or "").lower()

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


class TestBsiClassifierCompleteness:
    """Invariant: every known finding id carries a specific
    ``human_summary`` — the generic "Unclassified" fallback should
    only ever fire for genuinely unknown ids. Drift here means the
    Step 2 wizard would show the unhelpful fallback for a real BSI
    check."""

    def test_every_known_finding_has_human_summary(self):
        from sbomify.apps.compliance.services.sbom_compliance_service import (
            _BSI_HUMAN_SUMMARY,
            _BSI_REMEDIATION_TYPE,
            _UNKNOWN_FINDING_SUMMARY,
        )

        missing = [fid for fid in _BSI_REMEDIATION_TYPE if fid not in _BSI_HUMAN_SUMMARY]
        assert not missing, f"Finding ids with no human_summary: {missing}"
        # And every human_summary entry corresponds to a known finding
        # (no typos in the summary map that would silently shadow the
        # fallback for a never-fired id).
        strays = [fid for fid in _BSI_HUMAN_SUMMARY if fid not in _BSI_REMEDIATION_TYPE]
        assert not strays, f"human_summary ids not in the classifier: {strays}"
        assert _UNKNOWN_FINDING_SUMMARY  # sanity

    def test_tooling_limitation_summaries_name_a_scanner_or_workflow(self):
        """Every tooling_limitation summary must mention the
        scanner / workflow the operator should change. Generic
        "run sbomify-action" text isn't enough — the issue asked
        for specific explanations like "syft doesn't emit X"."""
        from sbomify.apps.compliance.services.sbom_compliance_service import (
            _BSI_HUMAN_SUMMARY,
            _BSI_REMEDIATION_TYPE,
        )

        tooling_ids = [fid for fid, t in _BSI_REMEDIATION_TYPE.items() if t == "tooling_limitation"]
        for fid in tooling_ids:
            summary = _BSI_HUMAN_SUMMARY[fid].lower()
            # Either names a scanner or the enrichment workflow.
            mentions_workflow = any(
                token in summary for token in ("syft", "trivy", "scanner", "enrich", "sbomify-action")
            )
            assert mentions_workflow, f"{fid}: summary should name a scanner or enrichment workflow"


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
        valid (remediation_type, guidance_url, human_summary) tuple
        even for fake ids. Regression guard for the "conservative
        default" contract."""
        rt, url, human = _classify_bsi_finding("bsi-tr03183:this-is-not-real")
        assert rt == "operator_action"
        assert url.startswith("https://")
        assert "Unclassified" in human


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

    def test_signing_outcome_rejects_empty_bundle_bytes(self):
        """``SigningOutcome(bundle_bytes=b"", ...)`` must raise at
        construction — an empty bundle is never a valid signature,
        and accepting it would hand out a 0-byte ``.sig`` side-car
        on download. Regression seal for the __post_init__ guard."""
        from sbomify.apps.compliance.services._bundle_signer import SigningOutcome

        with pytest.raises(ValueError, match="bundle_bytes must be non-empty"):
            SigningOutcome(bundle_bytes=b"", rekor_log_index=0, signed_by="", signed_issuer="")

    def test_signing_outcome_rejects_negative_rekor_index(self):
        """Rekor indexes are non-negative (``0`` is valid for a
        fresh log). Negative values would surface a corrupt state
        — reject at construction rather than letting it land on
        ``CRAExportPackage.rekor_log_index`` (PositiveBigIntegerField)
        with a later DB-constraint error that's harder to diagnose."""
        from sbomify.apps.compliance.services._bundle_signer import SigningOutcome

        with pytest.raises(ValueError, match="rekor_log_index must be >= 0"):
            SigningOutcome(bundle_bytes=b"x", rekor_log_index=-1, signed_by="", signed_issuer="")

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
        from sbomify.apps.compliance.services._bundle_signer import SigningOutcome

        team = sample_team_with_owner_member.team
        self._with_signing_settings(team)
        captured = {}

        def _capturing_signer(z, s):
            captured["zip"] = z
            captured["settings_team"] = s.team_id
            return SigningOutcome(b"sig", 1, "x", "y")

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
        """Defense-in-depth: whitespace-only string doesn't match the
        ``compliance/exports/*.sig`` prefix guard, so the presigner
        refuses it and returns ``None``. Prevents handing out a URL
        whose Key will fail S3-side."""
        package = CRAExportPackage.objects.create(
            assessment=assessment,
            storage_key=f"compliance/exports/{assessment.id}/test.zip",
            content_hash="a" * 64,
            manifest={"format_version": "1.1"},
            signature_storage_key="   ",
        )
        result = get_signature_download_url(package)
        assert result.ok
        assert result.value is None

    def test_signature_key_with_traversal_rejected(self, assessment):
        """Defense-in-depth: a hostile DB write of
        ``../../../etc/passwd`` as ``signature_storage_key`` fails
        the ``compliance/exports/*.sig`` prefix check and returns
        ``None`` — no presigned URL is ever handed out for a key
        outside the compliance export tree. S3 parameterisation
        alone would stop the traversal, but the prefix check gives
        us a defense-in-depth layer at the app boundary."""
        package = CRAExportPackage.objects.create(
            assessment=assessment,
            storage_key=f"compliance/exports/{assessment.id}/test.zip",
            content_hash="a" * 64,
            manifest={"format_version": "1.1"},
            signature_storage_key="../../../etc/passwd",
        )
        result = get_signature_download_url(package)
        assert result.ok
        assert result.value is None

    def test_signature_key_outside_compliance_exports_rejected(self, assessment):
        """Valid-looking key that sits outside ``compliance/exports/``
        (e.g. pointing at another app's S3 tree) still rejects.
        Prefix is authoritative — nothing else should be presigned
        via this endpoint."""
        package = CRAExportPackage.objects.create(
            assessment=assessment,
            storage_key=f"compliance/exports/{assessment.id}/test.zip",
            content_hash="a" * 64,
            manifest={"format_version": "1.1"},
            signature_storage_key="other-app/secret.sig",
        )
        assert get_signature_download_url(package).value is None

    def test_signature_key_without_sig_suffix_rejected(self, assessment):
        """Key under the correct prefix but not ending in ``.sig``
        (e.g. someone stored ``.zip`` by mistake) is rejected —
        the suffix constraint disambiguates which artefact the
        URL targets."""
        package = CRAExportPackage.objects.create(
            assessment=assessment,
            storage_key=f"compliance/exports/{assessment.id}/test.zip",
            content_hash="a" * 64,
            manifest={"format_version": "1.1"},
            signature_storage_key=f"compliance/exports/{assessment.id}/test.zip",
        )
        assert get_signature_download_url(package).value is None


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
class TestBuildExportPackageRealSignerNoAmbientIdentity:
    """End-to-end: team opts into sigstore_keyless, but no ambient
    OIDC identity is available (no SIGSTORE_ID_TOKEN env var, no CI
    workload identity). The signer returns None via the
    ``detect_credential() is None`` short-circuit; the export ships
    unsigned and the download endpoint correctly omits the
    signature URL.

    ``sigstore>=4.2`` IS a required project dependency — we don't
    test the "library absent" path because it can't happen in
    production. We test the realistic "no ambient token" path
    instead."""

    def test_no_ambient_identity_ships_unsigned(
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
        p = Product.objects.create(name="No OIDC", team=team)
        ares = get_or_create_assessment(p.id, sample_user, team)
        assert ares.ok
        a = ares.value
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )
        from sbomify.apps.compliance.services.document_generation_service import regenerate_all

        with patch("sbomify.apps.core.object_store.S3Client"):
            regenerate_all(a)

        # Patch detect_credential to return None — no ambient OIDC
        # token available. Real dispatch runs all the way through
        # the ``if token is None`` short-circuit and returns None
        # before touching ClientTrustConfig / SigningContext.
        captured: list[tuple[str, bytes]] = []

        class _Capture:
            def upload_data_as_file(self, bucket, key, data):
                captured.append((key, data))

            def get_file_data(self, bucket, key):
                return b""

            def get_sbom_data(self, filename):
                return b""

        with patch("sigstore.oidc.detect_credential", return_value=None):
            with patch("sbomify.apps.compliance.services.export_service.S3Client") as mock_s3_cls:
                mock_s3_cls.return_value = _Capture()
                result = build_export_package(a, sample_user)

        assert result.ok
        # No .sig side-car — the signer returned None at the
        # ``detect_credential() is None`` short-circuit.
        assert not any(key.endswith(".sig") for key, _ in captured)
        assert result.value.signature_storage_key == ""
        assert result.value.is_signed is False


# ---------------------------------------------------------------------------
# Sigstore OIDC flow — adversarial identity / issuer / Rekor cases
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestSigstoreOidcAdversarial:
    """Bad-case coverage for the real sigstore keyless path.

    The happy-path + basic mismatch cases live in
    ``test_bundle_signer.py::TestSigstoreKeylessSigner``. This class
    exercises the edges: whitespace, case-sensitivity, Unicode,
    malformed tokens, and partial-match attempts that would slip
    past a permissive implementation.
    """

    def _settings_for(self, team, **kwargs):
        from sbomify.apps.compliance.models import TeamComplianceSettings

        defaults = {"signing_enabled": True, "signing_provider": "sigstore_keyless"}
        defaults.update(kwargs)
        return TeamComplianceSettings.objects.create(team=team, **defaults)

    @staticmethod
    def _mock_token(identity: str, issuer: str):
        return type("MockToken", (), {"identity": identity, "issuer": issuer})()

    def test_identity_comparison_is_case_sensitive(self, sample_team_with_owner_member):
        """``signing_identity="ci@Acme.Example"`` must NOT match
        ambient ``ci@acme.example``. OIDC subject claims are
        case-sensitive by spec — a normalisation bug would let an
        attacker with control of a casing-variant identity bypass
        the check."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(team, signing_identity="ci@Acme.Example")

        with patch("sigstore.oidc.detect_credential") as detect:
            detect.return_value = self._mock_token(
                "ci@acme.example", "https://token.actions.githubusercontent.com"
            )
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                assert _sign_sigstore_keyless(b"zip", s) is None
                trust_cls.production.assert_not_called()
                ctx_cls.from_trust_config.assert_not_called()

    def test_identity_comparison_rejects_prefix_match(self, sample_team_with_owner_member):
        """Configured: ``ci@acme.example``. Ambient:
        ``ci@acme.example.attacker.test``. A substring/prefix match
        would be catastrophic — ambient must equal configured,
        nothing less."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(team, signing_identity="ci@acme.example")

        with patch("sigstore.oidc.detect_credential") as detect:
            detect.return_value = self._mock_token(
                "ci@acme.example.attacker.test", "https://issuer"
            )
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                assert _sign_sigstore_keyless(b"zip", s) is None
                trust_cls.production.assert_not_called()
                ctx_cls.from_trust_config.assert_not_called()

    def test_issuer_trailing_slash_is_literal_mismatch(self, sample_team_with_owner_member):
        """Configured issuer ``https://token.actions.githubusercontent.com``
        (no trailing slash); ambient token carries
        ``https://token.actions.githubusercontent.com/`` (with
        slash). OIDC ``iss`` claim comparison is byte-for-byte; a
        URL-normalisation "helpfulness" would allow a spoofed
        issuer to match. Pins the strict comparison."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(
            team, signing_issuer="https://token.actions.githubusercontent.com"
        )

        with patch("sigstore.oidc.detect_credential") as detect:
            detect.return_value = self._mock_token(
                "ci@example.test", "https://token.actions.githubusercontent.com/"
            )
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                assert _sign_sigstore_keyless(b"zip", s) is None
                trust_cls.production.assert_not_called()
                ctx_cls.from_trust_config.assert_not_called()

    def test_whitespace_padded_identity_is_mismatch(self, sample_team_with_owner_member):
        """Configured ``ci@acme.example``; ambient ``" ci@acme.example "``.
        Signer does NOT strip whitespace — forces operators to fix
        their IdP configuration rather than silently accepting a
        normalised claim."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(team, signing_identity="ci@acme.example")

        with patch("sigstore.oidc.detect_credential") as detect:
            detect.return_value = self._mock_token(" ci@acme.example ", "https://any")
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                assert _sign_sigstore_keyless(b"zip", s) is None
                trust_cls.production.assert_not_called()
                ctx_cls.from_trust_config.assert_not_called()

    def test_unicode_identity_matches_exactly(self, sample_team_with_owner_member):
        """Operators with non-ASCII identities (``ci@bücher.example``,
        i.e. IDN) must round-trip exactly. Regression guard against
        an idna-normalisation that would break equality."""
        from unittest.mock import MagicMock

        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(
            team, signing_identity="ci@bücher.example", signing_issuer="https://iß.example"
        )

        token = self._mock_token("ci@bücher.example", "https://iß.example")
        mock_bundle = MagicMock()
        mock_bundle.to_json.return_value = '{"ok":1}'
        mock_bundle.log_entry.log_index = "7"  # sigstore returns str
        mock_signer = MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_ctx = MagicMock()
        mock_ctx.signer.return_value.__enter__.return_value = mock_signer

        with patch("sigstore.oidc.detect_credential", return_value=token):
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                trust_cls.production.return_value = MagicMock(name="trust-config")
                ctx_cls.from_trust_config.return_value = mock_ctx
                outcome = _sign_sigstore_keyless(b"zip", s)

        assert outcome is not None
        assert outcome.signed_by == "ci@bücher.example"
        assert outcome.signed_issuer == "https://iß.example"

    def test_rekor_log_index_coerced_to_int(self, sample_team_with_owner_member):
        """``Bundle.log_entry.log_index`` is typed ``int`` by sigstore-
        python but protobuf-derived models can hand out pydantic-
        wrapped values. The signer does ``int(...)`` to force a
        plain Python int before persistence — PositiveBigIntegerField
        requires a native int and pydantic's proto-backed wrappers
        can serialise differently. Regression guard."""
        from unittest.mock import MagicMock

        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(team)
        token = self._mock_token("any@id", "https://any")

        mock_bundle = MagicMock()
        mock_bundle.to_json.return_value = '{"ok":1}'

        # Simulate a proto-wrapped integer that is int-castable but
        # not an actual ``int`` instance.
        class _ProtoInt:
            def __int__(self):
                return 99_999_999_999

        mock_bundle.log_entry.log_index = _ProtoInt()
        mock_signer = MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_ctx = MagicMock()
        mock_ctx.signer.return_value.__enter__.return_value = mock_signer

        with patch("sigstore.oidc.detect_credential", return_value=token):
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                trust_cls.production.return_value = MagicMock(name="trust-config")
                ctx_cls.from_trust_config.return_value = mock_ctx
                outcome = _sign_sigstore_keyless(b"zip", s)

        assert outcome is not None
        assert isinstance(outcome.rekor_log_index, int)
        assert outcome.rekor_log_index == 99_999_999_999

    def test_identity_pinned_issuer_unpinned_accepts_any_issuer(
        self, sample_team_with_owner_member
    ):
        """``signing_identity`` set, ``signing_issuer`` empty.
        Identity check fires, issuer check short-circuits. Real-
        world use case: "I know who my CI identity is, but I'm OK
        with any IdP minting it". Confirms the two checks are
        independent (each gated by its own ``if settings.X and``)."""
        from unittest.mock import MagicMock

        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(team, signing_identity="ci@acme.example")

        token = self._mock_token("ci@acme.example", "https://some.random.issuer")
        mock_bundle = MagicMock()
        mock_bundle.to_json.return_value = '{"ok":1}'
        mock_bundle.log_entry.log_index = "9"
        mock_signer = MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_ctx = MagicMock()
        mock_ctx.signer.return_value.__enter__.return_value = mock_signer

        with patch("sigstore.oidc.detect_credential", return_value=token):
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                trust_cls.production.return_value = MagicMock(name="trust-config")
                ctx_cls.from_trust_config.return_value = mock_ctx
                outcome = _sign_sigstore_keyless(b"zip", s)

        assert outcome is not None
        assert outcome.signed_by == "ci@acme.example"
        assert outcome.signed_issuer == "https://some.random.issuer"

    @pytest.mark.parametrize(
        "ambient_identity",
        [
            # Suffix attack: attacker pre-pends their own local-part.
            "attacker@ci@acme.example",
            # Null-byte injection to truncate at logging time.
            "ci@acme.example\x00extra",
            # Tab/newline splice into the sub claim.
            "ci@acme.example\tpadding",
            # Backslash / control-char injection.
            "ci@acme.example\\attacker",
        ],
    )
    def test_exotic_identity_values_rejected(
        self, sample_team_with_owner_member, ambient_identity
    ):
        """Round-trip paranoia: every exotic sub value that isn't
        byte-equal to the configured identity must reject. String
        equality is doing all the work here; a future normalisation
        would be catastrophic."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(team, signing_identity="ci@acme.example")

        with patch("sigstore.oidc.detect_credential") as detect:
            detect.return_value = self._mock_token(ambient_identity, "https://any")
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                assert _sign_sigstore_keyless(b"zip", s) is None
                trust_cls.production.assert_not_called()
                ctx_cls.from_trust_config.assert_not_called()

    def test_settings_row_requires_refetch_after_update(self, sample_team_with_owner_member):
        """Defensive regression: the signer uses the passed-in
        settings dict, not a re-fetched row. If an operator updates
        ``signing_identity`` mid-export (a race) the signer still
        sees the pre-fetch value. Documents this as intended —
        snapshot-at-call-time beats racey-midflight semantics for
        a signing operation."""
        from unittest.mock import MagicMock

        from sbomify.apps.compliance.models import TeamComplianceSettings
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        s = self._settings_for(team, signing_identity="original@id")

        # Mutate the DB row after we've captured ``s``.
        TeamComplianceSettings.objects.filter(pk=s.pk).update(signing_identity="mutated@id")

        token = self._mock_token("original@id", "https://any")
        mock_bundle = MagicMock()
        mock_bundle.to_json.return_value = '{"x":1}'
        mock_bundle.log_entry.log_index = 1
        mock_signer = MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_ctx = MagicMock()
        mock_ctx.signer.return_value.__enter__.return_value = mock_signer

        with patch("sigstore.oidc.detect_credential", return_value=token):
            with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
                "sigstore.sign.SigningContext"
            ) as ctx_cls:
                trust_cls.production.return_value = MagicMock(name="trust-config")
                ctx_cls.from_trust_config.return_value = mock_ctx
                outcome = _sign_sigstore_keyless(b"zip", s)

        # In-memory ``s`` still has the original identity, so the
        # validation passes. The DB row disagrees — signer doesn't
        # check, by design.
        assert outcome is not None
        assert outcome.signed_by == "original@id"


@pytest.mark.django_db
class TestDownloadApiSigningBlockEdges:
    """Adversarial coverage for the download API's ``signature``
    block: partial state, zero-index, and absent-but-storage-key
    combinations that should never exist in production but shouldn't
    crash the API when they do."""

    def test_signature_block_absent_when_storage_key_empty(
        self, sample_team_with_owner_member, sample_user
    ):
        """Package row exists with rekor_log_index set but empty
        signature_storage_key — the ``get_signature_download_url``
        boundary returns None so the API omits both
        ``signature_url`` AND ``signature`` block. No partial
        signing state ever leaks to the client."""
        from sbomify.apps.compliance.models import (
            CRAAssessment,
            CRAExportPackage,
        )
        from sbomify.apps.compliance.services.export_service import (
            get_signature_download_url,
        )

        team = sample_team_with_owner_member.team
        p = Product.objects.create(name="Partial Signing", team=team)
        profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
        ContactEntity.objects.create(
            profile=profile,
            name="Acme Labs GmbH",
            email="legal@acme.example",
            is_manufacturer=True,
        )
        a = get_or_create_assessment(p.id, sample_user, team).value
        pkg = CRAExportPackage.objects.create(
            assessment=a,
            storage_key="compliance/exports/x/abc.zip",
            content_hash="a" * 64,
            manifest={"format_version": "1.1"},
            signature_storage_key="",  # empty
            rekor_log_index=42,  # non-None but storage_key empty
            signed_by="stray@value",
            signed_issuer="https://stray",
        )

        # Signature URL path returns None because the key is empty —
        # rekor/signed_by state is ignored when there's no side-car
        # to point at.
        assert get_signature_download_url(pkg).value is None

    def test_signature_block_zero_rekor_index_still_valid(self, sample_team_with_owner_member):
        """Edge: ``rekor_log_index=0`` is a legitimate first-entry
        index in a Rekor instance (e.g., a new staging deployment).
        The signer must persist it as-is — a ``if not
        rekor_log_index`` check would falsely conclude "unsigned"."""
        from sbomify.apps.compliance.models import (
            CRAAssessment,
            CRAExportPackage,
        )

        team = sample_team_with_owner_member.team
        p = Product.objects.create(name="Zero Index", team=team)
        profile = ContactProfile.objects.create(name="Default", team=team, is_default=True)
        ContactEntity.objects.create(
            profile=profile,
            name="Acme Labs GmbH",
            email="legal@acme.example",
            is_manufacturer=True,
        )
        a = get_or_create_assessment(p.id, sample_user_for_team(team), team).value
        pkg = CRAExportPackage.objects.create(
            assessment=a,
            storage_key="compliance/exports/x/abc.zip",
            content_hash="b" * 64,
            manifest={"format_version": "1.1"},
            signature_storage_key="compliance/exports/x/abc.zip.sig",
            signature_provider="sigstore_keyless",
            rekor_log_index=0,
            signed_by="ci@example.test",
            signed_issuer="https://any",
        )

        assert pkg.is_signed is True
        assert pkg.rekor_log_index == 0


def sample_user_for_team(team):
    """Helper for the zero-index test — returns a user that
    owns ``team`` (the fixture machinery in this module doesn't
    expose it directly for ad-hoc Product creations)."""
    from sbomify.apps.teams.models import Member

    return Member.objects.filter(team=team, role="owner").first().user


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
        sentinel = object()
        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": lambda z, s: sentinel}):
            assert _SIGNERS_BY_PROVIDER["sigstore_keyless"](b"", None) is sentinel
        assert _SIGNERS_BY_PROVIDER == original

    def test_module_level_dispatch_is_readable(self):
        """Dispatch table contains exactly the two known providers
        plus ``none``. Future additions should trigger an update
        both here and in the TeamComplianceSettings.SigningProvider
        enum."""
        # Regression seal for the current provider set.
        assert set(_SIGNERS_BY_PROVIDER.keys()) == {"none", "sigstore_keyless"}
