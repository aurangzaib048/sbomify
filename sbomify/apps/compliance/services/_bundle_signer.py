"""Cosign / sigstore bundle-signing dispatcher for CRA exports.

Opt-in per team via :class:`TeamComplianceSettings` (issue #906). The
public entry point is :func:`sign_bundle`, which returns a
:class:`SigningOutcome` or ``None``:

    outcome = sign_bundle(zip_bytes, team)
    if outcome is not None:
        # outcome.bundle_bytes uploaded to S3 at f"{storage_key}.sig"
        # outcome.rekor_log_index + .signed_by + .signed_issuer
        # persisted on :class:`CRAExportPackage` for the audit trail.

``None`` is returned when the team hasn't enabled signing, when the
provider is configured but the runtime prerequisites aren't met
(missing ambient OIDC token, identity or issuer mismatch vs the
team's configured expectations), or when the signer itself raises.
In every case the bundle build still succeeds — signing is a
best-effort enhancement, not a gate on the export. A warning is
logged so operators can investigate misconfiguration without having
a regulated export blocked.

Produces a **Sigstore bundle v0.3** (``application/vnd.dev.sigstore.bundle.v0.3+json``)
in JSON form — the same shape consumed by the existing
``sbomify.apps.plugins.builtins.verification._verify_cosign_bundle``,
so a downstream CRA-bundle verifier can parse our output via
``sigstore.models.Bundle.from_json(...)`` and validate it with
``sigstore.verify.Verifier.production().verify_artifact(...)``. The
inverse round-trip is authoritative; this module is its mirror on
the producer side.

``sigstore>=4.2`` is a required dependency of the project (see
``pyproject.toml``); no import-time fallback is warranted. Runtime
failures (missing OIDC token, Fulcio unreachable, signer raises)
fall through to the outer ``sign_bundle`` catch — the export ships
unsigned with a logged warning.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sbomify.apps.compliance.models import TeamComplianceSettings
    from sbomify.apps.teams.models import Team


@dataclass(frozen=True)
class SigningOutcome:
    """Structured result of a successful signing pass.

    Carries everything that needs to be persisted on
    :class:`CRAExportPackage` for the audit trail:
      - ``bundle_bytes``: the Sigstore bundle JSON (uploaded to S3
        at ``<storage_key>.sig``). Rejected if empty — an empty
        bundle would still pass the truthiness check in the outer
        caller but would hand out a 0-byte side-car on download.
      - ``rekor_log_index``: the Rekor transparency-log index of the
        signing entry. ``0`` is a legitimate first-entry index in a
        fresh Rekor instance; negative values are rejected.
      - ``signed_by``: the OIDC subject that was ATTESTED TO —
        always matches ``settings.signing_identity`` when configured
        (enforced by the signer before returning).
      - ``signed_issuer``: the OIDC issuer URL ditto.
    """

    bundle_bytes: bytes
    rekor_log_index: int
    signed_by: str
    signed_issuer: str

    def __post_init__(self) -> None:
        # Reject shapes that would misrepresent a successful signing —
        # truthy-but-nonsense values slip past the "non-None means
        # signed" check at the call site.
        if not self.bundle_bytes:
            raise ValueError("SigningOutcome.bundle_bytes must be non-empty")
        if self.rekor_log_index < 0:
            raise ValueError(f"SigningOutcome.rekor_log_index must be >= 0, got {self.rekor_log_index}")


SigningCallable = Callable[[bytes, "TeamComplianceSettings"], "SigningOutcome | None"]


def _sign_noop(zip_bytes: bytes, settings: "TeamComplianceSettings") -> "SigningOutcome | None":
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


def _sign_sigstore_keyless(zip_bytes: bytes, settings: "TeamComplianceSettings") -> "SigningOutcome | None":
    """Sigstore keyless signing via Fulcio-issued ephemeral certs.

    Implements the full OIDC flow:

    1. Resolve the ambient OIDC identity via ``detect_credential()``.
       Checks ``SIGSTORE_ID_TOKEN`` env var, GitHub Actions workflow
       token, GCP / AWS / Azure ambient identity, and interactive
       OAuth (the last is disabled in server contexts but the same
       entrypoint). Returns ``None`` when no identity is available.

    2. Validate the resolved subject against
       ``settings.signing_identity`` — the ``sub`` claim of the
       ambient token must match the team's configured identity.
       Prevents the "server's local service account silently signs
       in place of the CI identity" class of bug. Empty
       ``signing_identity`` disables the check (first-time setup).

    3. Validate the issuer against ``settings.signing_issuer`` —
       the ``iss`` claim must match. Pins the OIDC provider so a
       token from a different issuer (same email, wrong IdP) is
       rejected.

    4. Sign via ``SigningContext.from_trust_config(ClientTrustConfig.production())``
       which uses Sigstore's public Fulcio + Rekor instances. The
       Bundle returned by ``Signer.sign_artifact`` already contains
       the log-entry inclusion proof — we capture ``log_index`` for
       persistence on :class:`CRAExportPackage`.

    Every rejection path returns ``None``; the outer ``sign_bundle``
    wrapper logs + returns ``None`` so the export ships unsigned.
    The bundle bytes round-trip through
    ``sbomify.apps.plugins.builtins.verification._verify_cosign_bundle``
    (same Sigstore bundle v0.3 JSON format) so a downstream
    verifier can confirm the signature without sbomify-specific
    knowledge.
    """
    # sigstore 4.2 API: SigningContext is constructed from a
    # ClientTrustConfig, not via a .production() classmethod. That
    # method DOES exist on ClientTrustConfig (and on Verifier) but
    # not on SigningContext — the asymmetry is easy to miss because
    # MagicMock would autocreate it silently in tests.
    from sigstore.models import ClientTrustConfig  # type: ignore[import-not-found,unused-ignore]
    from sigstore.oidc import detect_credential  # type: ignore[import-not-found,unused-ignore]
    from sigstore.sign import SigningContext  # type: ignore[import-not-found,unused-ignore]

    token = detect_credential()
    if token is None:
        logger.warning(
            "Sigstore keyless signing enabled for team %s but no ambient "
            "OIDC identity is available (set SIGSTORE_ID_TOKEN or run under "
            "a supported CI with workload identity); exporting unsigned.",
            settings.team_id,
        )
        return None

    token_identity: str = token.identity  # type: ignore[attr-defined]
    token_issuer: str = token.issuer  # type: ignore[attr-defined]

    if settings.signing_identity and token_identity != settings.signing_identity:
        logger.warning(
            "Sigstore identity mismatch for team %s: configured=%r, ambient=%r; "
            "exporting unsigned to prevent impersonation.",
            settings.team_id,
            settings.signing_identity,
            token_identity,
        )
        return None

    if settings.signing_issuer and token_issuer != settings.signing_issuer:
        logger.warning(
            "Sigstore issuer mismatch for team %s: configured=%r, ambient=%r; "
            "exporting unsigned to prevent cross-IdP substitution.",
            settings.team_id,
            settings.signing_issuer,
            token_issuer,
        )
        return None

    trust_config = ClientTrustConfig.production()
    ctx = SigningContext.from_trust_config(trust_config)
    with ctx.signer(token) as signer:  # type: ignore[arg-type,unused-ignore]
        bundle = signer.sign_artifact(zip_bytes)

    return SigningOutcome(
        bundle_bytes=bundle.to_json().encode("utf-8"),
        rekor_log_index=int(bundle.log_entry.log_index),  # type: ignore[attr-defined,unused-ignore]
        signed_by=token_identity,
        signed_issuer=token_issuer,
    )


# Dispatch table. Tests override entries here to inject deterministic
# mock signers without touching sigstore at all.
_SIGNERS_BY_PROVIDER: dict[str, SigningCallable] = {
    "none": _sign_noop,
    "sigstore_keyless": _sign_sigstore_keyless,
}


def sign_bundle(zip_bytes: bytes, team: "Team") -> "SigningOutcome | None":
    """Return a :class:`SigningOutcome` for ``zip_bytes``, or ``None``.

    Resolves the team's :class:`TeamComplianceSettings`. Returns
    ``None`` when:

    - the team has no ``compliance_settings`` row (default state)
    - ``signing_enabled`` is ``False``
    - the configured provider can't produce a signature right now
      (missing OIDC token, identity/issuer mismatch, runtime
      failure, provider callable raises)

    This is the public contract: the caller at
    ``build_export_package`` must be able to treat signing as
    best-effort. Exceptions raised by a provider callable are caught
    and logged here so a single broken signer can't kill a regulated
    export. The non-None return carries the Sigstore bundle bytes
    plus the Rekor log index plus the resolved OIDC identity that
    was attested to — all persisted on :class:`CRAExportPackage`
    for the audit trail.
    """
    from sbomify.apps.compliance.models import TeamComplianceSettings

    try:
        settings = team.compliance_settings
    except TeamComplianceSettings.DoesNotExist:
        # Default state: no settings row. Silent return — signing
        # isn't enabled so there's nothing to log about.
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

    try:
        return signer(zip_bytes, settings)
    except Exception:  # pragma: no cover - exercised via mock
        # Per the docstring: never propagate a signer failure. A
        # broken provider must not fail the export — the bundle ships
        # unsigned, the manifest records no signature, the download
        # endpoint correctly hides the signature_url affordance.
        logger.exception(
            "Signer %s raised for team %s; exporting unsigned.",
            settings.signing_provider,
            team.id,
        )
        return None
