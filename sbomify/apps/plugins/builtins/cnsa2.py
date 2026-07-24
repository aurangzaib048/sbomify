"""NSA CNSA 2.0 compliance assessment plugin.

Grades each algorithm asset against the CNSA 2.0 allow-list for National
Security Systems: AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87, and the
SP 800-208 stateful hash-based signatures (LMS, XMSS). CNSA 1.0 holdovers
(RSA/DH at 3072+ bits, ECDSA/ECDH on P-384) warn with the transition
deadline; everything else fails in an NSS context. This mirrors what
CBOMkit's quantum_safe.rego policy evaluates.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sbomify.apps.plugins.sdk import Finding
from sbomify.apps.sboms.crypto_inventory import CryptoAsset, CryptoInventory
from sbomify.apps.sboms.pqc import asset_identity_haystack, identity_tokens

from ._crypto_assessment import CryptoInventoryPlugin, curve_bits, key_bits

logger = logging.getLogger(__name__)

_PLUGIN_NAME = "cnsa-2.0"
_DEADLINE = "2033"

_SEVERITY = {"fail": "high", "warning": "medium", "pass": "info", "info": "info"}  # nosec B105 - severity labels

_REMEDIATION_FAIL = (
    "Adopt a CNSA 2.0 algorithm: ML-KEM-1024 for key establishment, ML-DSA-87 for signatures, "
    "LMS/XMSS for firmware signing, AES-256 for encryption, SHA-384 or SHA-512 for hashing."
)
_REMEDIATION_TRANSITIONAL = (
    f"CNSA 1.0 algorithms are transitional: NSS must move to CNSA 2.0, exclusively by {_DEADLINE} "
    "(software and firmware signing earlier, per the NSA timeline)."
)

_STATEFUL_HASH_SIGS = ("xmss", "lms", "hss")


@dataclass(frozen=True)
class _Verdict:
    status: str  # fail | warning | pass | info
    label: str
    reason: str


def _param_digits(hay: str) -> set[int]:
    import re

    return {int(n) for n in re.findall(r"\d{2,5}", hay)}


def classify_cnsa(asset: CryptoAsset) -> _Verdict:  # noqa: C901 - one ordered rule table
    hay = asset_identity_haystack(asset)
    tokens = identity_tokens(hay)
    digits = _param_digits(hay)

    if any(s in hay for s in _STATEFUL_HASH_SIGS):
        return _Verdict("pass", "CNSA 2.0", "SP 800-208 stateful hash-based signatures are CNSA 2.0 approved")

    if "ml-kem" in hay or "mlkem" in hay or "kyber" in hay:
        if 1024 in digits:
            return _Verdict("pass", "CNSA 2.0", "ML-KEM-1024 is the CNSA 2.0 key-establishment algorithm")
        if digits & {512, 768}:
            return _Verdict("fail", "Non-compliant", "CNSA 2.0 requires the ML-KEM-1024 parameter set")
        return _Verdict("warning", "Parameter set unclear", "Declare the parameter set; CNSA 2.0 requires ML-KEM-1024")

    if "ml-dsa" in hay or "mldsa" in hay or "dilithium" in hay:
        if 87 in digits or "dilithium5" in hay.replace(" ", ""):
            return _Verdict("pass", "CNSA 2.0", "ML-DSA-87 is the CNSA 2.0 signature algorithm")
        if digits & {44, 65}:
            return _Verdict("fail", "Non-compliant", "CNSA 2.0 requires the ML-DSA-87 parameter set")
        return _Verdict("warning", "Parameter set unclear", "Declare the parameter set; CNSA 2.0 requires ML-DSA-87")

    if "slh-dsa" in hay or "slhdsa" in hay or "sphincs" in hay:
        return _Verdict("fail", "Non-compliant", "SLH-DSA is not in the CNSA 2.0 algorithm suite")

    if "aes" in tokens:
        if 256 in digits:
            return _Verdict("pass", "CNSA 2.0", "AES-256 is the CNSA 2.0 symmetric cipher")
        if digits & {128, 192}:
            return _Verdict("fail", "Non-compliant", "CNSA 2.0 requires 256-bit AES keys")
        return _Verdict("warning", "Key size unclear", "Declare the key size; CNSA 2.0 requires AES-256")

    if "sha" in hay:
        if digits & {384, 512}:
            return _Verdict("pass", "CNSA 2.0", "SHA-384/SHA-512 are the CNSA 2.0 hash functions")
        return _Verdict("fail", "Non-compliant", "CNSA 2.0 permits only SHA-384 and SHA-512 for hashing")

    if any(s in hay for s in ("ecdsa", "ecdh", "secp", "brainpool", "nistp")) or {"ec", "ecc"} & tokens:
        bits = curve_bits(asset, hay)
        if bits == 384:
            return _Verdict(
                "warning",
                "CNSA 1.0 transitional",
                f"P-384 is CNSA 1.0; NSS must transition to CNSA 2.0 algorithms by {_DEADLINE}",
            )
        return _Verdict("fail", "Non-compliant", "CNSA permits only curve P-384, and only transitionally")

    if any(s in hay for s in ("ed25519", "ed448", "x25519", "x448", "curve25519", "curve448")):
        return _Verdict("fail", "Non-compliant", "Edwards/Montgomery curves are not in the CNSA suite")

    if "rsa" in tokens or {"dh", "dhe", "ffdh"} & tokens or "diffie" in hay:
        bits = key_bits(hay)
        if bits is not None and bits >= 3072:
            return _Verdict(
                "warning",
                "CNSA 1.0 transitional",
                f"{bits}-bit keys are CNSA 1.0; NSS must transition to CNSA 2.0 algorithms by {_DEADLINE}",
            )
        return _Verdict("fail", "Non-compliant", "CNSA 1.0 requires at least 3072-bit keys, and only transitionally")

    legacy = ("md5", "md4", "md2", "rc4", "rc2", "arcfour", "skipjack", "chacha", "poly1305", "salsa20")
    if any(s in hay for s in legacy) or {"des", "3des", "tdea"} & tokens:
        return _Verdict("fail", "Non-compliant", "Algorithm is not in the CNSA suite")
    return _Verdict("info", "Not recognized", "Algorithm not recognized; verify against the CNSA 2.0 suite manually")


class Cnsa2Plugin(CryptoInventoryPlugin):
    """Grade crypto assets against the NSA CNSA 2.0 algorithm suite."""

    PLUGIN_NAME = _PLUGIN_NAME
    VERSION = "1.0.0"
    STANDARD_NAME = "NSA CNSA 2.0"
    STANDARD_VERSION = "September 2022 advisory"
    STANDARD_URL = "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
    ERROR_TITLE = "CNSA 2.0 assessment error"
    EMPTY_DESCRIPTION = "This document declares no crypto-asset components; nothing to assess."

    def build_findings(self, inventory: CryptoInventory, sbom_id: str) -> list[Finding]:
        return [self._finding(index, asset) for index, asset in enumerate(inventory.assets)]

    def _finding(self, index: int, asset: CryptoAsset) -> Finding:
        name = asset.name or "Unnamed asset"
        finding_id = f"{_PLUGIN_NAME}:{asset.bom_ref or asset.name or f'asset-{index}'}"

        verdict = classify_cnsa(asset)
        if verdict.label == "Not recognized" and asset.asset_type is not None and asset.asset_type != "algorithm":
            kind = asset.asset_type.replace("-", " ")
            return Finding(
                id=finding_id,
                title=f"{name}: {kind} (not assessed)",
                description=f"{kind.capitalize()} assets are not assessed against CNSA 2.0 by this check.",
                status="info",
                severity="info",
                metadata={"cnsa_status": "not_assessed", "asset_type": asset.asset_type, "asset_name": asset.name},
            )

        remediation = None
        if verdict.status == "fail":
            remediation = _REMEDIATION_FAIL
        elif verdict.label == "CNSA 1.0 transitional":
            remediation = _REMEDIATION_TRANSITIONAL
        return Finding(
            id=finding_id,
            title=f"{name}: {verdict.label}",
            description=verdict.reason,
            status=verdict.status,
            severity=_SEVERITY[verdict.status],
            remediation=remediation,
            metadata={
                "cnsa_status": verdict.label.lower().replace(" ", "_").replace(".", "_"),
                "asset_type": asset.asset_type,
                "asset_name": asset.name,
            },
        )
