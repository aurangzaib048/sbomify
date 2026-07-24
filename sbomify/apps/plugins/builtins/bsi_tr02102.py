"""BSI TR-02102 crypto-mechanisms assessment plugin.

Grades algorithm and protocol assets against BSI TR-02102 (Cryptographic
Mechanisms: Recommendations and Key Lengths): 3000-bit floor for RSA/DH/DSA,
250-bit floor for elliptic curves, mode checks for block ciphers, and the
TR-02102-2 TLS version ladder. Complements the bsi-tr03183 plugin, which
checks the SBOM document itself rather than the cryptography it declares.

Notable divergences from the NIST checks: RSA-2048 fails outright (BSI's
floor is 3000 bits), SHA-224 fails (below BSI's 120-bit security floor), and
FrodoKEM and Classic McEliece pass (BSI recommends both; NIST standardized
neither).
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

_PLUGIN_NAME = "bsi-tr02102"

_SEVERITY = {"fail": "high", "warning": "medium", "pass": "info", "info": "info"}  # nosec B105 - severity labels

_REMEDIATION_FAIL = (
    "Move to a TR-02102-1 recommended mechanism: AES (GCM/CCM), SHA-2/SHA-3, RSA or DH at "
    "3000+ bits, elliptic curves at 250+ bits, or a recommended PQC scheme (ML-KEM, FrodoKEM, "
    "Classic McEliece)."
)

_RECOMMENDED_PQC = (
    "ml-kem",
    "mlkem",
    "kyber",
    "ml-dsa",
    "mldsa",
    "dilithium",
    "frodo",
    "mceliece",
    "xmss",
    "lms",
    "hss",
)
_LEGACY_CIPHER_MARKERS = ("3des", "tdea", "des-ede", "desede", "des3", "triple des", "tripledes", "triple-des")
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


def _classify_tls(version: str | None) -> _Verdict:
    try:
        parsed = float(version) if version else None
    except ValueError:
        parsed = None
    if parsed is None:
        return _Verdict("info", "Version not declared", "TLS version not declared; cannot grade against TR-02102-2")
    if parsed < 1.2:
        return _Verdict("fail", "Not recommended", f"TLS {version} is not recommended by TR-02102-2; use TLS 1.3")
    if parsed < 1.3:
        return _Verdict(
            "warning",
            "Conditional",
            "TLS 1.2 is only recommended with the TR-02102-2 condition list (approved suites, PFS); prefer TLS 1.3",
        )
    return _Verdict("pass", "Recommended", f"TLS {version} is recommended by TR-02102-2")


def classify_bsi(asset: CryptoAsset) -> _Verdict:  # noqa: C901 - one ordered rule table
    if asset.asset_type == "protocol":
        protocol = asset.protocol or {}
        proto_type = str(protocol.get("type") or "").lower()
        if proto_type == "tls" or "tls" in (asset.name or "").lower():
            return _classify_tls(str(protocol.get("version")) if protocol.get("version") is not None else None)
        return _Verdict("info", "Not assessed", "Non-TLS protocols are not assessed against TR-02102-2 by this check")

    hay = asset_identity_haystack(asset)
    tokens = identity_tokens(hay)
    mode = (asset.mode or "").lower()

    if any(s in hay for s in _RECOMMENDED_PQC):
        return _Verdict("pass", "Recommended", "TR-02102-1 recommended post-quantum or hash-based mechanism")

    if any(s in hay for s in ("md5", "md4", "md2")):
        return _Verdict("fail", "Not recommended", "MD-family hashes fall far below the TR-02102-1 security floor")
    if any(t in tokens for t in ("rc4", "rc2", "arcfour")) or "skipjack" in hay:
        return _Verdict("fail", "Not recommended", "Legacy stream/block cipher outside TR-02102-1 recommendations")
    if any(s in hay for s in _LEGACY_CIPHER_MARKERS) or "des" in tokens:
        return _Verdict("fail", "Not recommended", "DES/TDEA are not recommended by TR-02102-1")

    if "hmac" in hay:
        if _SHA1_RE.search(hay):
            return _Verdict("warning", "Below recommendation", "HMAC-SHA-1 falls below the TR-02102-1 hash floor")
        return _Verdict("pass", "Recommended", "HMAC with a SHA-2/SHA-3 hash is recommended")
    if _SHA1_RE.search(hay) or _SHA224_RE.search(hay):
        return _Verdict("fail", "Not recommended", "Hashes below 240-bit output fall under the TR-02102-1 floor")
    if _APPROVED_HASH_RE.search(hay):
        return _Verdict("pass", "Recommended", "SHA-2/SHA-3 at 256+ bits is recommended")

    if "aes" in tokens:
        if mode == "ecb" or "ecb" in tokens:
            return _Verdict("fail", "Not recommended", "ECB mode leaks plaintext structure; use GCM or CCM")
        if mode == "cbc" or "cbc" in tokens:
            return _Verdict("warning", "Conditional", "Plain CBC is padding-oracle prone; prefer GCM or CCM")
        return _Verdict("pass", "Recommended", "AES is recommended at 128-bit keys and above")
    if any(s in hay for s in _OUT_OF_SCOPE):
        return _Verdict("info", "Out of scope", "Not in the TR-02102-1 recommended-mechanisms list")

    if any(s in hay for s in _EDWARDS):
        return _Verdict("pass", "Recommended", "~255-bit Edwards/Montgomery curve meets the 250-bit floor")
    if any(s in hay for s in _EC_MARKERS) or {"ec", "ecc"} & tokens:
        bits = curve_bits(asset, hay)
        if bits is None:
            return _Verdict("info", "Size not declared", "Curve size not declared; cannot verify the 250-bit floor")
        if bits < 250:
            return _Verdict("fail", "Not recommended", f"{bits}-bit curves fall below the TR-02102-1 250-bit floor")
        return _Verdict("pass", "Recommended", f"{bits}-bit curve meets the TR-02102-1 250-bit floor")

    if "dsa" in tokens or "rsa" in tokens or {"dh", "dhe", "ffdh"} & tokens or "diffie" in hay:
        bits = key_bits(hay)
        if bits is None:
            return _Verdict("info", "Size not declared", "Key size not declared; cannot verify the 3000-bit floor")
        if bits < 3000:
            return _Verdict("fail", "Not recommended", f"{bits}-bit keys fall below the TR-02102-1 3000-bit floor")
        return _Verdict("pass", "Recommended", f"{bits}-bit key meets the TR-02102-1 3000-bit floor")

    return _Verdict("info", "Not recognized", "Mechanism not recognized; verify against TR-02102-1 manually")


class BsiTr02102Plugin(CryptoInventoryPlugin):
    """Grade crypto mechanisms against BSI TR-02102 recommendations."""

    PLUGIN_NAME = _PLUGIN_NAME
    VERSION = "1.0.0"
    STANDARD_NAME = "BSI TR-02102 Cryptographic Mechanisms"
    STANDARD_VERSION = "TR-02102-1/-2 (2026-01)"
    STANDARD_URL = (
        "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/"
        "Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html"
    )
    ERROR_TITLE = "BSI TR-02102 assessment error"
    EMPTY_DESCRIPTION = "This document declares no crypto-asset components; nothing to assess."

    def build_findings(self, inventory: CryptoInventory, sbom_id: str) -> list[Finding]:
        return [self._finding(index, asset) for index, asset in enumerate(inventory.assets)]

    def _finding(self, index: int, asset: CryptoAsset) -> Finding:
        name = asset.name or "Unnamed asset"
        finding_id = f"{_PLUGIN_NAME}:{asset.bom_ref or asset.name or f'asset-{index}'}"
        verdict = classify_bsi(asset)

        if (
            verdict.label == "Not recognized"
            and asset.asset_type is not None
            and asset.asset_type not in ("algorithm", "protocol")
        ):
            kind = asset.asset_type.replace("-", " ")
            return Finding(
                id=finding_id,
                title=f"{name}: {kind} (not assessed)",
                description=f"{kind.capitalize()} assets are not assessed against TR-02102 by this check.",
                status="info",
                severity="info",
                metadata={"bsi_status": "not_assessed", "asset_type": asset.asset_type, "asset_name": asset.name},
            )

        return Finding(
            id=finding_id,
            title=f"{name}: {verdict.label}",
            description=verdict.reason,
            status=verdict.status,
            severity=_SEVERITY[verdict.status],
            remediation=_REMEDIATION_FAIL if verdict.status == "fail" else None,
            metadata={
                "bsi_status": verdict.label.lower().replace(" ", "_"),
                "asset_type": asset.asset_type,
                "asset_name": asset.name,
            },
        )
