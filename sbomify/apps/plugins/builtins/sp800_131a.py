"""NIST SP 800-131A legacy-algorithm transitions assessment plugin.

Grades each cryptographic asset in a CycloneDX document against the SP 800-131A
transition schedule (Rev 2 final plus the Rev 3 draft sunsets). This is the
classical-security counterpart to the pqc-readiness plugin: MD5 and SHA-1 fail
here today while the PQC classifier only marks them needs-review.

Verdicts:

- ``fail`` — disallowed or never approved (DES, Skipjack, RC4, MD2/4/5, TDEA
  encryption, DSA or SHA-1 signature generation, sub-112-bit key sizes).
- ``warning`` — deprecated with a sunset (SHA-1 outside signing, the 224-bit
  hash family, and 112-bit strength, all through 2030-12-31 per the Rev 3
  draft), plus verify/decrypt-only legacy allowances.
- ``pass`` — approved algorithms at acceptable strength.
- ``info`` — non-algorithm assets, algorithms outside NIST scope, unrecognized
  names, and approved families with no declared size.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sbomify.apps.plugins.sdk import Finding
from sbomify.apps.sboms.crypto_inventory import CryptoAsset, CryptoInventory
from sbomify.apps.sboms.pqc import asset_identity_haystack, identity_tokens

from ._crypto_assessment import CryptoInventoryPlugin, curve_bits, key_bits

logger = logging.getLogger(__name__)

_PLUGIN_NAME = "nist-sp800-131a"
_SUNSET = "2030-12-31"

_SEVERITY = {"fail": "high", "warning": "medium", "pass": "info", "info": "info"}  # nosec B105 - severity labels

_REMEDIATION_FAIL = (
    "Replace with an approved algorithm at 128-bit strength or better (AES, SHA-2/SHA-3, "
    "RSA-3072, ECDSA P-256, or a FIPS 203/204/205 post-quantum algorithm)."
)
_REMEDIATION_DEPRECATED = (
    f"Plan migration before {_SUNSET}: NIST SP 800-131A Rev 3 (draft) disallows this use after the sunset date."
)

_PQC_APPROVED = ("ml-kem", "mlkem", "kyber", "ml-dsa", "mldsa", "dilithium", "slh-dsa", "slhdsa", "sphincs")
_STATEFUL_HASH_SIGS = ("xmss", "lms", "hss")
_PQC_NOT_FINAL = ("fn-dsa", "falcon", "hqc", "bike", "mceliece", "frodo", "ntru", "saber")
_TDEA_MARKERS = ("3des", "tdea", "des-ede", "desede", "des3", "triple des", "tripledes", "triple-des")
_SHA1_RE = re.compile(r"sha[-_ ]?1(?![0-9])")
_SHA224_RE = re.compile(r"sha3?[-_ ]?224|512[/_-]224")
_APPROVED_HASH_RE = re.compile(r"sha3?[-_ ]?(256|384|512)(?![0-9/])|shake")
_EDWARDS = ("ed25519", "ed448", "x25519", "x448", "curve25519", "curve448")
_EC_MARKERS = ("ecdsa", "ecdh", "secp", "sect", "brainpool", "prime256v1", "nistp", "ecmqv", "ecies")
_OUT_OF_SCOPE = ("chacha", "poly1305", "salsa20")


@dataclass(frozen=True)
class _Verdict:
    status: str  # fail | warning | pass | info
    label: str
    reason: str
    sunset: str | None = None


def classify_transition(asset: CryptoAsset) -> _Verdict:  # noqa: C901 - one ordered rule table
    hay = asset_identity_haystack(asset)
    tokens = identity_tokens(hay)
    funcs = {f.lower() for f in asset.crypto_functions}
    signs = "sign" in funcs or (not funcs and (asset.primitive or "").lower() == "signature")

    if any(s in hay for s in _PQC_APPROVED):
        return _Verdict("pass", "Approved", "FIPS 203/204/205 approved post-quantum algorithm")
    if any(s in hay for s in _STATEFUL_HASH_SIGS):
        return _Verdict("pass", "Approved", "SP 800-208 approved stateful hash-based signature")
    if any(s in hay for s in _PQC_NOT_FINAL):
        return _Verdict("info", "Not yet approved", "Post-quantum candidate without a final FIPS standard")

    if any(s in hay for s in ("md5", "md4", "md2")):
        return _Verdict("fail", "Disallowed", "MD-family hashes were never approved for applying protection")
    if any(t in tokens for t in ("rc4", "rc2", "arcfour")) or "skipjack" in hay:
        return _Verdict("fail", "Disallowed", "Never approved or withdrawn cipher (SP 800-131A)")

    if any(s in hay for s in _TDEA_MARKERS):
        if funcs and "encrypt" not in funcs and "decrypt" in funcs:
            return _Verdict("warning", "Legacy use", "TDEA decryption is legacy-use only (SP 800-131A Rev 2)")
        return _Verdict("fail", "Disallowed", "TDEA encryption is disallowed after 2023 (SP 800-131A Rev 2)")
    if "des" in tokens:
        return _Verdict("fail", "Disallowed", "Single DES has been disallowed since 2005")

    if "hmac" in hay:
        if _SHA1_RE.search(hay):
            return _Verdict(
                "warning",
                "Deprecated",
                f"HMAC-SHA-1 is deprecated through {_SUNSET} and disallowed after (Rev 3 draft)",
                sunset=_SUNSET,
            )
        return _Verdict("pass", "Approved", "HMAC with an approved hash is acceptable")
    if _SHA1_RE.search(hay):
        if signs:
            return _Verdict("fail", "Disallowed", "SHA-1 digital signature generation has been disallowed since 2014")
        return _Verdict(
            "warning",
            "Deprecated",
            f"SHA-1 is deprecated for all protection uses through {_SUNSET}, disallowed after (Rev 3 draft)",
            sunset=_SUNSET,
        )
    if _SHA224_RE.search(hay):
        return _Verdict(
            "warning",
            "Deprecated",
            f"The 224-bit hash family is deprecated through {_SUNSET}, disallowed after (Rev 3 draft)",
            sunset=_SUNSET,
        )
    if _APPROVED_HASH_RE.search(hay):
        return _Verdict("pass", "Approved", "FIPS 180-4 / FIPS 202 approved hash")

    if "aes" in tokens:
        return _Verdict("pass", "Approved", "AES is approved at all standard key sizes")
    if any(s in hay for s in _OUT_OF_SCOPE):
        return _Verdict("info", "Out of scope", "Not a NIST-approved algorithm; outside SP 800-131A scope")

    if any(s in hay for s in _EDWARDS):
        return _Verdict("pass", "Approved", "FIPS 186-5 / SP 800-186 approved Edwards or Montgomery curve")
    if any(s in hay for s in _EC_MARKERS) or {"ec", "ecc"} & tokens:
        bits = curve_bits(asset, hay)
        if bits is None:
            return _Verdict("info", "Size not declared", "Curve size not declared; cannot verify against minimums")
        if bits < 224:
            return _Verdict("fail", "Disallowed", f"{bits}-bit curves fall below the 112-bit strength minimum")
        if bits < 256:
            return _Verdict(
                "warning",
                "Deprecated",
                f"112-bit strength ({bits}-bit curve) is deprecated through {_SUNSET} (Rev 3 draft)",
                sunset=_SUNSET,
            )
        return _Verdict("pass", "Approved", f"{bits}-bit curve meets the 128-bit strength minimum")

    if "dsa" in tokens:
        if funcs and funcs <= {"verify"}:
            return _Verdict("warning", "Legacy use", "DSA signature verification is legacy-use only (FIPS 186-5)")
        return _Verdict("fail", "Disallowed", "DSA signature generation was removed in FIPS 186-5")

    if "rsa" in tokens or {"dh", "dhe", "ffdh"} & tokens or "diffie" in hay:
        bits = key_bits(hay)
        if bits is None:
            return _Verdict("info", "Size not declared", "Key size not declared; cannot verify against minimums")
        if bits < 2048:
            return _Verdict("fail", "Disallowed", f"{bits}-bit keys fall below the 112-bit strength minimum")
        if bits < 3072:
            return _Verdict(
                "warning",
                "Deprecated",
                f"112-bit strength ({bits}-bit key) is deprecated through {_SUNSET} (Rev 3 draft)",
                sunset=_SUNSET,
            )
        return _Verdict("pass", "Approved", f"{bits}-bit key meets the 128-bit strength minimum")

    return _Verdict("info", "Not recognized", "Algorithm not recognized; verify its transition status manually")


class Sp800131aPlugin(CryptoInventoryPlugin):
    """Flag algorithms that SP 800-131A has transitioned out of approved use."""

    PLUGIN_NAME = _PLUGIN_NAME
    VERSION = "1.0.0"
    STANDARD_NAME = "NIST SP 800-131A Transitions"
    STANDARD_VERSION = "Rev 2 (Rev 3 draft sunsets)"
    STANDARD_URL = "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
    ERROR_TITLE = "SP 800-131A assessment error"
    EMPTY_DESCRIPTION = "This document declares no crypto-asset components; nothing to assess."

    def build_findings(self, inventory: CryptoInventory, sbom_id: str) -> list[Finding]:
        return [self._finding(index, asset) for index, asset in enumerate(inventory.assets)]

    def _finding(self, index: int, asset: CryptoAsset) -> Finding:
        name = asset.name or "Unnamed asset"
        finding_id = f"{_PLUGIN_NAME}:{asset.bom_ref or asset.name or f'asset-{index}'}"
        verdict = classify_transition(asset)

        # A non-algorithm asset whose identity does not resolve to an algorithm
        # is out of this check's scope, mirroring pqc-readiness.
        if verdict.label == "Not recognized" and asset.asset_type is not None and asset.asset_type != "algorithm":
            kind = asset.asset_type.replace("-", " ")
            return Finding(
                id=finding_id,
                title=f"{name} — {kind} (not assessed)",
                description=f"{kind.capitalize()} assets are not assessed for algorithm transitions by this check.",
                status="info",
                severity="info",
                metadata={
                    "transition_status": "not_assessed",
                    "asset_type": asset.asset_type,
                    "asset_name": asset.name,
                },
            )

        remediation = None
        if verdict.status == "fail":
            remediation = _REMEDIATION_FAIL
        elif verdict.sunset:
            remediation = _REMEDIATION_DEPRECATED
        finding_metadata = {
            "transition_status": verdict.label.lower().replace(" ", "_"),
            "asset_type": asset.asset_type,
            "asset_name": asset.name,
        }
        if verdict.sunset:
            finding_metadata["sunset"] = verdict.sunset
        return Finding(
            id=finding_id,
            title=f"{name} — {verdict.label}",
            description=verdict.reason,
            status=verdict.status,
            severity=_SEVERITY[verdict.status],
            remediation=remediation,
            metadata=finding_metadata,
        )
