"""Unit tests for :mod:`sbomify.apps.compliance.services._bundle_signer`.

Issue #906: the signer is opt-in per team, never blocks an export on
failure, and dispatches on the configured provider. Tests cover the
three states from the acceptance criteria:

- Signing disabled (default) → ``None``, no log.
- Signing enabled + provider configured + mock signer happy path
  → signature bytes returned.
- Signing enabled + provider raises / returns ``None`` → ``None``,
  warning logged, bundle still exports.

The ``sigstore`` library itself is an optional dependency. Every
test mocks the dispatch table directly so the suite passes on
environments without ``sigstore`` installed.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sbomify.apps.compliance.models import TeamComplianceSettings
from sbomify.apps.compliance.services._bundle_signer import (
    _SIGNERS_BY_PROVIDER,
    sign_bundle,
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
        provider typo) must not raise — the signer returns None so
        the bundle still ships unsigned. A warning is logged (via
        the module logger) but the project's logging setup doesn't
        propagate to pytest's caplog, so we assert only on the
        return value here."""
        team = sample_team_with_owner_member.team
        # Bypass the model's choices validation by writing to the
        # underlying field attribute directly — this simulates a DB
        # row where the enum was extended without the code catching up.
        settings = TeamComplianceSettings(team=team, signing_enabled=True)
        settings.signing_provider = "future-provider-v2"
        settings.save()

        assert sign_bundle(b"zip-bytes", team) is None

    def test_happy_path_returns_signature_bytes(self, sample_team_with_owner_member):
        """Override the dispatch table with a deterministic mock
        signer and confirm the bytes flow through ``sign_bundle``
        unchanged. Keeps the test free of sigstore / OIDC
        infrastructure."""
        team = sample_team_with_owner_member.team
        TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )

        mock_sig = b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}'
        with patch.dict(_SIGNERS_BY_PROVIDER, {"sigstore_keyless": lambda z, s: mock_sig}):
            assert sign_bundle(b"zip-bytes", team) == mock_sig

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
            # Contract: sign_bundle catches and returns None.
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
    """The real sigstore dispatch path. Only assertion today is
    that the library being absent is handled gracefully — full
    end-to-end OIDC signing is a follow-up issue."""

    def test_missing_sigstore_library_returns_none(self, sample_team_with_owner_member):
        """When ``import sigstore.sign`` raises ``ImportError``
        (default in test environment), the signer returns None so
        the export ships unsigned instead of crashing the build."""
        from sbomify.apps.compliance.services._bundle_signer import _sign_sigstore_keyless

        team = sample_team_with_owner_member.team
        settings = TeamComplianceSettings.objects.create(
            team=team, signing_enabled=True, signing_provider="sigstore_keyless"
        )

        result = _sign_sigstore_keyless(b"zip-bytes", settings)

        assert result is None
