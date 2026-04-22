"""Cosign / sigstore bundle-signing dispatcher for CRA exports.

Opt-in per team via :class:`TeamComplianceSettings` (issue #906). The
public entry point is :func:`sign_bundle`:

    signature = sign_bundle(zip_bytes, team)
    if signature:
        # upload to S3 at f"{storage_key}.sig"

``signature`` is ``None`` when the team hasn't enabled signing, when
the provider is configured but the runtime prerequisites aren't met
(e.g. missing OIDC token for keyless), or when the signer itself
raises. In every case the bundle build still succeeds — signing is a
best-effort enhancement, not a gate on the export. A warning is
logged so operators can investigate misconfiguration without having
a regulated export blocked.

Real sigstore-python integration is behind a feature check because
``sigstore`` is an optional dependency in this repo. When the
library is missing, the keyless provider logs once and returns
``None``; tests mock the signer directly via
:data:`_SIGNERS_BY_PROVIDER` so they don't depend on sigstore being
installed.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sbomify.apps.compliance.models import TeamComplianceSettings
    from sbomify.apps.teams.models import Team


SigningCallable = Callable[[bytes, "TeamComplianceSettings"], bytes | None]


def _sign_noop(zip_bytes: bytes, settings: "TeamComplianceSettings") -> bytes | None:
    """No-op signer — returned when ``signing_provider == "none"``.

    Kept separate from the "signing disabled" short-circuit so a
    team that flips the toggle without picking a provider gets a
    distinguishable log message instead of a silent no-sig bundle.
    """
    logger.info(
        "Team %s has signing_enabled=True but signing_provider=none; "
        "no signature will be produced until a provider is selected.",
        settings.team_id,
    )
    return None


def _sign_sigstore_keyless(zip_bytes: bytes, settings: "TeamComplianceSettings") -> bytes | None:
    """Sigstore keyless signing via Fulcio-issued ephemeral certs.

    Requires the ``sigstore`` Python package + an ambient OIDC
    identity (env var ``SIGSTORE_OIDC_TOKEN`` or the server's
    ambient credential chain) at signing time. When either is
    missing, logs a warning and returns ``None`` so the export can
    still ship — signing is a layered enhancement, not a gate.
    """
    try:
        from sigstore.sign import SigningContext  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        logger.warning(
            "Team %s has sigstore_keyless signing enabled but the sigstore "
            "Python package is not installed; signature skipped. "
            "Install sigstore>=3.0 to enable.",
            settings.team_id,
        )
        return None

    try:
        # The signing flow below is intentionally minimal — a full
        # production implementation will negotiate the OIDC flow via
        # the sbomify server's configured issuer, resolve the
        # expected subject against ``settings.signing_identity``, and
        # upload the transparency-log entry to Rekor. That's more
        # infrastructure than fits in this PR; the follow-up issue
        # tracks the remaining work. Today we use the sigstore
        # library's ``SigningContext.production()`` which picks up
        # ambient OIDC identity when available.
        ctx = SigningContext.production()  # type: ignore[attr-defined,unused-ignore]
        with ctx.signer() as signer:  # type: ignore[attr-defined,unused-ignore]
            result = signer.sign_artifact(zip_bytes)
        return bytes(result.to_bundle().to_json(), "utf-8")
    except Exception:  # pragma: no cover - exercised via mock
        logger.exception(
            "Sigstore keyless signing failed for team %s; exporting unsigned.",
            settings.team_id,
        )
        return None


# Dispatch table. Tests override entries here to inject deterministic
# mock signers without touching sigstore at all.
_SIGNERS_BY_PROVIDER: dict[str, SigningCallable] = {
    "none": _sign_noop,
    "sigstore_keyless": _sign_sigstore_keyless,
}


def sign_bundle(zip_bytes: bytes, team: "Team") -> bytes | None:
    """Return signature bytes for ``zip_bytes``, or ``None``.

    Resolves the team's :class:`TeamComplianceSettings`. Returns
    ``None`` when:

    - the team has no ``compliance_settings`` row (default state)
    - ``signing_enabled`` is ``False``
    - the configured provider can't produce a signature right now
      (missing dep, missing OIDC token, runtime failure)

    The non-None return is raw signature bytes — typically a Sigstore
    bundle JSON — that the caller persists as a side-car object in S3.
    """
    try:
        settings = team.compliance_settings
    except Exception:
        # Missing settings row is the default "signing disabled"
        # state; no log, no signature.
        return None

    if not settings.signing_enabled:
        return None

    signer = _SIGNERS_BY_PROVIDER.get(settings.signing_provider)
    if signer is None:
        logger.warning(
            "Team %s has signing_enabled=True with unknown provider %r; "
            "signature skipped. Extend _SIGNERS_BY_PROVIDER to add support.",
            team.id,
            settings.signing_provider,
        )
        return None

    return signer(zip_bytes, settings)
