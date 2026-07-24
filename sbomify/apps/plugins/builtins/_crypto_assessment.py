"""Shared scaffolding for crypto-inventory assessment plugins.

The crypto policy plugins (SP 800-131A, BSI TR-02102, certificate lifecycle,
CNSA 2.0) all follow the same shape: parse the immutable artifact, derive the
crypto inventory, emit one finding per asset the check applies to. This base
centralizes that shape; subclasses supply a ``build_findings``.

Empty inventories skip quietly here — pqc-readiness alone owns the visible
"CBOM with no crypto assets" misfire warning, so an empty CBOM does not stack
one warning per enabled crypto plugin.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbomify.apps.plugins.sdk import (
    AssessmentCategory,
    AssessmentPlugin,
    AssessmentResult,
    AssessmentSummary,
    Finding,
    PluginMetadata,
    ScanMode,
)
from sbomify.apps.plugins.sdk.base import SBOMContext
from sbomify.apps.sboms.crypto_inventory import CryptoAsset, CryptoInventory, derive_crypto_inventory


def strip_hash_names(hay: str) -> str:
    """Remove sha-N tokens so a signature-hash suffix is not read as a key size."""
    return re.sub(r"sha3?[-_ ]?\d+(?:[/_-]\d+)?", " ", hay)


def key_bits(hay: str, minimum: int = 512) -> int | None:
    """Largest plausible key size in an identity haystack, hash names excluded."""
    sizes = [int(n) for n in re.findall(r"\d{3,5}", strip_hash_names(hay))]
    plausible = [n for n in sizes if n >= minimum]
    return max(plausible) if plausible else None


_KNOWN_CURVE_BITS = {160, 163, 192, 224, 233, 239, 256, 283, 320, 384, 409, 512, 521, 571}


def curve_bits(asset: CryptoAsset, hay: str) -> int | None:
    """Curve size from the asset's curve fields, falling back to its name."""
    for field in (asset.normalized_curve, asset.curve, asset.parameter_set, strip_hash_names(hay)):
        if not field:
            continue
        sizes = [int(n) for n in re.findall(r"\d{3}", field.lower()) if int(n) in _KNOWN_CURVE_BITS]
        if sizes:
            return sizes[0]
    return None


def summarize(findings: list[Finding]) -> AssessmentSummary:
    return AssessmentSummary(
        total_findings=len(findings),
        pass_count=sum(1 for f in findings if f.status == "pass"),
        fail_count=sum(1 for f in findings if f.status == "fail"),
        warning_count=sum(1 for f in findings if f.status == "warning"),
        error_count=sum(1 for f in findings if f.status == "error"),
        info_count=sum(1 for f in findings if f.status == "info"),
    )


class CryptoInventoryPlugin(AssessmentPlugin):
    """Template for plugins that grade the derived crypto inventory."""

    PLUGIN_NAME: str = ""
    VERSION: str = "1.0.0"
    STANDARD_NAME: str = ""
    STANDARD_VERSION: str = ""
    STANDARD_URL: str = ""
    ERROR_TITLE: str = "Assessment error"
    EMPTY_DESCRIPTION: str = "This document declares no assets this check applies to; nothing to assess."

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.PLUGIN_NAME,
            version=self.VERSION,
            category=AssessmentCategory.COMPLIANCE,
            scan_mode=ScanMode.ONE_SHOT,
            supported_bom_types=["cbom", "sbom"],
            requires_crypto_assets=True,
        )

    def build_findings(self, inventory: CryptoInventory, sbom_id: str) -> list[Finding]:
        raise NotImplementedError

    def assess(
        self,
        sbom_id: str,
        sbom_path: Path,
        dependency_status: dict[str, Any] | None = None,
        context: SBOMContext | None = None,
    ) -> AssessmentResult:
        try:
            document = json.loads(sbom_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
            return self._error_result(f"Invalid JSON: {exc}")
        except OSError as exc:  # pragma: no cover - defensive
            return self._error_result(f"Failed to read SBOM: {exc}")

        if not isinstance(document, dict):
            return self._error_result("SBOM is not a JSON object")

        findings = self.build_findings(derive_crypto_inventory(document), sbom_id)
        metadata: dict[str, Any] = {
            "standard_name": self.STANDARD_NAME,
            "standard_version": self.STANDARD_VERSION,
            "standard_url": self.STANDARD_URL,
        }
        if not findings:
            metadata["skipped"] = True
            findings = [
                Finding(
                    id=f"{self.PLUGIN_NAME}:no-assets",
                    title="Nothing to assess",
                    description=self.EMPTY_DESCRIPTION,
                    status="info",
                    severity="info",
                )
            ]

        return AssessmentResult(
            plugin_name=self.PLUGIN_NAME,
            plugin_version=self.VERSION,
            category=AssessmentCategory.COMPLIANCE.value,
            assessed_at=datetime.now(timezone.utc).isoformat(),
            summary=summarize(findings),
            findings=findings,
            metadata=metadata,
        )

    def _error_result(self, message: str) -> AssessmentResult:
        return AssessmentResult(
            plugin_name=self.PLUGIN_NAME,
            plugin_version=self.VERSION,
            category=AssessmentCategory.COMPLIANCE.value,
            assessed_at=datetime.now(timezone.utc).isoformat(),
            summary=AssessmentSummary(total_findings=1, error_count=1),
            findings=[
                Finding(
                    id=f"{self.PLUGIN_NAME}:error",
                    title=self.ERROR_TITLE,
                    description=message,
                    status="error",
                    severity="high",
                )
            ],
            metadata={"error": True},
        )
