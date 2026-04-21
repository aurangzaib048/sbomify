"""Shared loaders for CRA reference data shipped alongside the app.

Centralises the path to ``oscal_data/cra-harmonised-standards.json`` and
the ``read_bytes`` / ``json.loads`` wrappers around it so the two
compliance services (document generation and export) don't maintain
parallel constants that can drift.

Ships with a minimal built-in fallback so a broken deploy (packaging
mistake, missing file, corrupt JSON) degrades to "CRA + BSI TR-03183-2
only" on the Declaration of Conformity rather than raising out of
``generate_document`` and blocking every export.
"""

from __future__ import annotations

import functools
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

HARMONISED_STANDARDS_PATH: Path = (
    Path(__file__).resolve().parent.parent / "reference_data" / "cra-harmonised-standards.json"
)

# Safe fallback when the shipped JSON is missing or corrupt. Matches the
# structure of the full file but only carries the two ``always_applicable``
# anchors (the CRA itself and BSI TR-03183-2 for SBOM format) — enough to
# satisfy Annex V item 6 minimally so the DoC still renders a valid
# standards section. Flagged via ``_is_fallback`` so tests / logs can
# detect the degraded state.
_MINIMAL_FALLBACK: dict[str, Any] = {
    "format_version": "1.0",
    "description": "Fallback reference data — the shipped JSON was missing or unreadable.",
    "_is_fallback": True,
    "standards": [
        {
            "id": "cra",
            "citation": "Regulation (EU) 2024/2847 — Cyber Resilience Act",
            "url": "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng",
            "harmonised": False,
            "always_applicable": True,
            "cra_requirements_covered": [],
        },
        {
            "id": "bsi-tr-03183-2",
            "citation": "BSI TR-03183-2 v2.1.0 — Cyber Resilience Requirements, Part 2: SBOM",
            "url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.html",
            "harmonised": False,
            "always_applicable": True,
            "cra_requirements_covered": [
                {
                    "cra_reference": "Annex I, Part II, §1",
                    "summary": "SBOM covering top-level dependencies in a commonly used machine-readable format.",
                }
            ],
        },
    ],
}


def read_harmonised_standards_bytes() -> bytes | None:
    """Return the raw JSON bytes, or None if the file is missing / unreadable.

    Used by the export service to embed the reference data in the bundle.
    Returning None signals "skip the embedded copy"; the DoC section still
    renders via :func:`load_harmonised_standards` which has its own fallback.
    """
    try:
        return HARMONISED_STANDARDS_PATH.read_bytes()
    except OSError:
        logger.exception("cra-harmonised-standards.json missing from installed app")
        return None


@functools.cache
def load_harmonised_standards() -> dict[str, Any]:
    """Load + cache the reference data, or return the minimal fallback.

    Fallback triggers on:
    - File missing / unreadable (``OSError``)
    - Invalid JSON (``json.JSONDecodeError``)

    Either case is an install-time bug, not a runtime one. We log once
    at error level, then return a minimal in-memory payload so the DoC
    still emits a valid Annex V §6 "Standards & Specifications Applied"
    section instead of blocking the whole export pipeline.
    """
    try:
        raw = HARMONISED_STANDARDS_PATH.read_text(encoding="utf-8")
    except OSError:
        logger.exception("cra-harmonised-standards.json unreadable; falling back to minimal in-memory list")
        return _MINIMAL_FALLBACK
    try:
        data: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError:
        logger.exception("cra-harmonised-standards.json is not valid JSON; falling back to minimal in-memory list")
        return _MINIMAL_FALLBACK
    return data
