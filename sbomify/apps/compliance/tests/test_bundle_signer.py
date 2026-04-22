"""Unit tests for :mod:`sbomify.apps.compliance.services._bundle_signer`.

Issue #906: the signer is opt-in per team, never blocks an export on
failure, and dispatches on the configured provider. Tests cover the
four state families:

- Signing disabled / unconfigured (default) → ``None``, no log.
- Signing enabled + mock signer happy path → ``SigningOutcome``
  returned verbatim.
- Signing enabled + provider raises / returns ``None`` → ``None``,
  warning logged, bundle still exports.
- Real sigstore dispatch with no ambient OIDC identity → ``None``
  via ``detect_credential()`` returning ``None``.

``sigstore>=4.2`` is a required project dependency (see
``pyproject.toml``); the signer imports unconditionally. Tests
mock the dispatch table with deterministic signers that return
``SigningOutcome`` so the suite doesn't depend on real OIDC
infrastructure.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sbomify.apps.compliance.models import TeamComplianceSettings
from sbomify.apps.compliance.services._bundle_signer import (
    _SIGNERS_BY_PROVIDER,
    SigningOutcome,
    sign_bundle,
)


def _mock_outcome(
    signed_by: str = "ci@example.test",
    signed_issuer: str = "https://token.actions.githubusercontent.com",
    rekor_log_index: int = 123456,
) -> SigningOutcome:
    """Test helper — a deterministic SigningOutcome for dispatch mocking."""
    return SigningOutcome(
        bundle_bytes=b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}',
        rekor_log_index=rekor_log_index,
        signed_by=signed_by,
        signed_issuer=signed_issuer,
    )


@pytest.mark.django_db
class TestSignBundleDispatch:
    def test_team_without_settings_returns_none(self, sample_team_with_owner_member):
        """The default state — no ``TeamComplianceSettings`` row for
        the team — must short-circuit cleanly to None so an
        unconfigured team exports the same unsigned bundle it did
        before the feature landed (no regression)."""
        team = sample_team_with_owner_member.team
        assert sign_bundle(b"zip-bytes", team) is None

    def test_disabled_setting_returns_none(self, sample_team_with_owner_member):
        team = sample_team_with_owner_member.team
        TeamComplianceSettings.objects.create(team=team, signing_enabled=False)

        assert sign_bundle(b"zip-bytes", team) is None

    def test_enabled_with_provider_none_returns_none(self, sample_team_with_owner_member):
        """Flipping ``signing_enabled=True`` without picking a
        provider must not crash — the "none" provider logs and
        returns None. Covers the ``_sign_noop`` branch."""
        team = sample_team_with_owner_member.team
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="none"
        )

        assert sign_bundle(b"zip-bytes", team) is None

    def test_unknown_provider_returns_none(self, sample_team_with_owner_member):
        """Provider string that isn't in the dispatch table (future-
        provider typo) must not raise — the signer returns None."""
        team = sample_team_with_owner_member.team
        settings = TeamComplianceSettings(team=team, signing_enabled=True)
        settings.signing_provider = "future-provider-v2"
        settings.save()

        assert sign_bundle(b"zip-bytes", team) is None

    def test_happy_path_returns_signing_outcome(self, sample_team_with_owner_member):
        """Override the dispatch table with a deterministic mock
        signer returning ``SigningOutcome`` and confirm
        ``sign_bundle`` forwards the full structured result so the
        caller can persist Rekor + identity fields on
        :class:`CRAExportPackage`."""
        team = sample_team_with_owner_member.team
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )
        outcome = _mock_outcome(rekor_log_index=987654321)
        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": lambda z, s: outcome}):
            result = sign_bundle(b"zip-bytes", team)

        assert result is outcome
        assert result.rekor_log_index == 987654321
        assert result.signed_by == "ci@example.test"
        assert result.signed_issuer == "https://token.actions.githubusercontent.com"

    def test_signer_runtime_failure_is_swallowed(self, sample_team_with_owner_member):
        """A signer that raises must never propagate — the bundle
        export pipeline stays signing-agnostic. This is the contract
        stated on ``sign_bundle``: signing is best-effort; a broken
        provider must not fail a regulated export."""
        team = sample_team_with_owner_member.team
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )

        def _raising_signer(z, s):
            raise RuntimeError("fulcio unreachable")

        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": _raising_signer}):
            assert sign_bundle(b"zip-bytes", team) is None

    def test_signer_returning_none_passes_through(self, sample_team_with_owner_member):
        """Providers that can't produce a signature right now (e.g.
        missing OIDC token) return ``None`` — ``sign_bundle``
        forwards that to its caller so the export still ships."""
        team = sample_team_with_owner_member.team
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )

        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": lambda z, s: None}):
            assert sign_bundle(b"zip-bytes", team) is None


@pytest.mark.django_db
class TestSigstoreKeylessSigner:
    """Real sigstore dispatch path, mocked at the
    :func:`sigstore.oidc.detect_credential` boundary so we can
    exercise identity/issuer validation without a real OIDC token."""

    def test_no_ambient_oidc_token_exports_unsigned(self, sample_team_with_owner_member):
        """``detect_credential()`` returns None (no SIGSTORE_ID_TOKEN,
        no ambient CI identity) — the signer returns None cleanly,
        no SigningContext work attempted."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        settings = TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )

        with patch("sigstore.oidc.detect_credential", return_value=None):
            assert _sign_sigstore_keyless(b"zip-bytes", settings) is None

    def test_identity_mismatch_rejects_signing(self, sample_team_with_owner_member):
        """Team configured ``signing_identity="ci@acme.example"`` but
        ambient token carries ``sub="root@deploy-vm"``. Signer must
        reject before touching Fulcio so the wrong identity is
        never attested to."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        settings = TeamComplianceSettings.objects.create(
            team=team,
            signing_enabled=True,
            signing_provider="sigstore_keyless",
            signing_identity="ci@acme.example",
        )
        mock_token = type(
            "MockToken",
            (),
            {"identity": "root@deploy-vm", "issuer": "https://accounts.google.com"},
        )()
        with patch("sigstore.oidc.detect_credential", return_value=mock_token):
            # Even if SigningContext were called, it would blow up —
            # patch it too so a rejection regression surfaces as a
            # crash in the test, not silently producing a signature.
            with patch("sigstore.sign.SigningContext") as ctx_cls:
                result = _sign_sigstore_keyless(b"zip-bytes", settings)
                ctx_cls.production.assert_not_called()

        assert result is None

    def test_issuer_mismatch_rejects_signing(self, sample_team_with_owner_member):
        """Team configured to require GitHub Actions OIDC, but
        ambient token came from Google. Reject — cross-IdP
        substitution."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        settings = TeamComplianceSettings.objects.create(
            team=team,
            signing_enabled=True,
            signing_provider="sigstore_keyless",
            signing_issuer="https://token.actions.githubusercontent.com",
        )
        mock_token = type(
            "MockToken",
            (),
            {"identity": "ci@acme.example", "issuer": "https://accounts.google.com"},
        )()
        with patch("sigstore.oidc.detect_credential", return_value=mock_token):
            with patch("sigstore.sign.SigningContext") as ctx_cls:
                result = _sign_sigstore_keyless(b"zip-bytes", settings)
                ctx_cls.production.assert_not_called()

        assert result is None

    def test_happy_path_resolves_identity_and_captures_rekor(
        self, sample_team_with_owner_member
    ):
        """Full end-to-end with the sigstore API mocked: ambient
        token resolves, identity + issuer match, sign_artifact
        returns a Bundle-shaped mock with ``log_entry.log_index``,
        and the signer produces a SigningOutcome with every field
        populated from the resolved state."""
        from unittest.mock import MagicMock

        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        settings = TeamComplianceSettings.objects.create(
            team=team,
            signing_enabled=True,
            signing_provider="sigstore_keyless",
            signing_identity="ci@acme.example",
            signing_issuer="https://token.actions.githubusercontent.com",
        )

        mock_token = type(
            "MockToken",
            (),
            {
                "identity": "ci@acme.example",
                "issuer": "https://token.actions.githubusercontent.com",
            },
        )()

        mock_bundle = MagicMock()
        mock_bundle.to_json.return_value = '{"mediaType":"test-bundle"}'
        mock_bundle.log_entry.log_index = 42

        mock_signer = MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_ctx = MagicMock()
        mock_ctx.signer.return_value.__enter__.return_value = mock_signer

        with patch("sigstore.oidc.detect_credential", return_value=mock_token):
            with patch("sigstore.sign.SigningContext") as ctx_cls:
                ctx_cls.production.return_value = mock_ctx
                outcome = _sign_sigstore_keyless(b"zip-bytes", settings)

        assert outcome is not None
        assert outcome.bundle_bytes == b'{"mediaType":"test-bundle"}'
        assert outcome.rekor_log_index == 42
        assert outcome.signed_by == "ci@acme.example"
        assert outcome.signed_issuer == "https://token.actions.githubusercontent.com"
        # The ambient token was passed to SigningContext.signer(...)
        # — that's the mechanism by which identity validation is
        # binding (sigstore-python uses the token to request the
        # Fulcio cert).
        mock_ctx.signer.assert_called_once_with(mock_token)

    def test_unconfigured_identity_accepts_any_subject(self, sample_team_with_owner_member):
        """Teams with empty ``signing_identity`` accept any ambient
        subject — the common "first-time setup" state where the
        operator hasn't picked which identity to pin to yet. Still
        signs successfully; the subject resolved from the ambient
        token is persisted on the export package so an auditor can
        see who actually signed."""
        from unittest.mock import MagicMock

        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        settings = TeamComplianceSettings.objects.create(
            team=team,
            signing_enabled=True,
            signing_provider="sigstore_keyless",
            # No signing_identity or signing_issuer configured.
        )

        mock_token = type(
            "MockToken",
            (),
            {"identity": "whoever@dev.local", "issuer": "https://any.issuer"},
        )()
        mock_bundle = MagicMock()
        mock_bundle.to_json.return_value = '{"mediaType":"test"}'
        mock_bundle.log_entry.log_index = 1
        mock_signer = MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_ctx = MagicMock()
        mock_ctx.signer.return_value.__enter__.return_value = mock_signer

        with patch("sigstore.oidc.detect_credential", return_value=mock_token):
            with patch("sigstore.sign.SigningContext") as ctx_cls:
                ctx_cls.production.return_value = mock_ctx
                outcome = _sign_sigstore_keyless(b"zip-bytes", settings)

        assert outcome is not None
        assert outcome.signed_by == "whoever@dev.local"

    def test_signing_context_failure_propagates_to_outer_swallow(
        self, sample_team_with_owner_member
    ):
        """Sigstore raises inside the context manager (Fulcio
        unreachable, clock skew, invalid token). Contract: the
        inner signer doesn't catch — it propagates to the outer
        ``sign_bundle`` wrapper which swallows. Pins the error-
        propagation boundary so a future "be helpful" catch doesn't
        silently hide identity errors."""
        from sbomify.apps.compliance.services._bundle_signer import (
            _sign_sigstore_keyless,
            sign_bundle,
        )

        team = sample_team_with_owner_member.team
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )
        mock_token = type(
            "MockToken",
            (),
            {"identity": "ci@example.test", "issuer": "https://any"},
        )()

        with patch("sigstore.oidc.detect_credential", return_value=mock_token):
            with patch("sigstore.sign.SigningContext") as ctx_cls:
                ctx_cls.production.side_effect = RuntimeError("Fulcio unreachable")
                # Inner signer propagates.
                with pytest.raises(RuntimeError):
                    _sign_sigstore_keyless(
                        b"zip-bytes", TeamComplianceSettings.objects.get(team=team)
                    )
                # Outer wrapper swallows.
                assert sign_bundle(b"zip-bytes", team) is None
