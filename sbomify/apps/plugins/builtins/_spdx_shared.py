"""Shared SPDX 2.x helpers used by multiple compliance plugins.

The FDA and CISA plugins both need to identify the BOM subject (DESCRIBES
target) and filter document-level OTHER annotations by subject. Keeping
one implementation here prevents the two plugins from drifting in their
interpretation of SPDX 2.3 §12 Annotation semantics.
"""

from __future__ import annotations

from typing import Any


def spdx2_root_spdxid(data: dict[str, Any]) -> str | None:
    """Return the SPDXID of the BOM subject for an SPDX 2.x document.

    Prefers documentDescribes[0]. Falls back to the first DESCRIBES
    relationship whose spdxElementId is SPDXRef-DOCUMENT.

    Returns None when no root can be identified.
    """
    describes = data.get("documentDescribes")
    if isinstance(describes, list) and describes:
        first = describes[0]
        if isinstance(first, str) and first:
            return first
    for rel in data.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        if str(rel.get("relationshipType") or "").upper() != "DESCRIBES":
            continue
        if rel.get("spdxElementId") != "SPDXRef-DOCUMENT":
            continue
        related = rel.get("relatedSpdxElement")
        if isinstance(related, str) and related:
            return related
    return None


def spdx2_annotation_targets_document(annotation: dict[str, Any], root_spdxid: str | None) -> bool:
    """Return True if a top-level SPDX 2.x annotation describes the
    document or the BOM subject (root).

    Per SPDX 2.3 §12 Annotation, an annotation with spdxElementId pointing
    at a specific package describes that package, not the document — so
    such annotations must not satisfy the narrow doc-level fallback.

    Lenient-but-safe handling of empty / missing spdxElementId:
    - Empty is accepted as document-scoped only when the document declares
      a DESCRIBES target (root_spdxid is not None). Real-world SPDX tools
      often omit spdxElementId on document-level annotations and pair
      them with a DESCRIBES relationship, so this preserves interoperability.
    - When the document has no DESCRIBES target, an annotation without an
      explicit spdxElementId is ambiguous and must be rejected so a crafted
      SBOM cannot inflate the compliance score via an unanchored annotation.
    """
    subject = annotation.get("spdxElementId", "")
    if not isinstance(subject, str):
        return False
    if subject == "SPDXRef-DOCUMENT":
        return True
    if subject == "":
        return root_spdxid is not None
    return root_spdxid is not None and subject == root_spdxid
