"""Shared SPDX helpers used by multiple compliance plugins.

Covers both SPDX 2.x and SPDX 3.x. FDA and CISA plugins share this
module so their interpretation of SPDX 2.3 §12 (annotation subject
scope) and SPDX 3.0.1 rootElement semantics stay consistent.
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


def spdx3_document_subjects(data: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Return (document_ids, root_element_ids) for an SPDX 3.x document.

    Per SPDX 3.0.1 Core.SpdxDocument:
      - spdxId of the SpdxDocument element itself identifies the document.
      - rootElement lists the "interesting" element(s) of the contained tree
        (the BOM subject). The spec explicitly forbids rootElement being
        of type SpdxDocument, so the two sets are disjoint by design.

    Returning them separately lets callers enforce stricter scoping rules
    (e.g. "empty-subject annotation is document-scoped only when at least
    one rootElement has been declared" — analogous to SPDX 2.x requiring
    a DESCRIBES target before lenient empty-subject handling kicks in).
    """
    document_ids: set[str] = set()
    root_element_ids: set[str] = set()
    for element in data.get("@graph", data.get("elements", [])):
        elem_type = element.get("type", element.get("@type", ""))
        if "SpdxDocument" not in elem_type:
            continue
        doc_id = element.get("spdxId", element.get("@id", ""))
        if isinstance(doc_id, str) and doc_id:
            document_ids.add(doc_id)
        for root in element.get("rootElement", []) or []:
            if isinstance(root, str) and root:
                root_element_ids.add(root)
    return document_ids, root_element_ids


def spdx3_annotation_subject_matches(
    element: dict[str, Any],
    document_ids: set[str],
    root_element_ids: set[str],
) -> bool:
    """Return True if an SPDX 3.x Annotation targets the document or
    one of its rootElements.

    Empty subject is accepted as document-scoped only when at least one
    rootElement has been declared. This mirrors the SPDX 2.x rule that
    empty spdxElementId is only acceptable when a DESCRIBES target
    exists. Without any rootElement the annotation is unanchored — a
    malformed / crafted SBOM can't inflate the compliance score by
    dropping in a subject-less annotation.
    """
    subject = element.get("subject", element.get("annotationSubject", ""))
    if not isinstance(subject, str):
        return False
    if subject == "":
        return bool(root_element_ids)
    return subject in document_ids or subject in root_element_ids
