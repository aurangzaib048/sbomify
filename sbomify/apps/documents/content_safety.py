"""Helpers to serve user-uploaded document bytes without enabling stored XSS.

A document's content and its ``content_type`` are attacker-controlled: the
browser-supplied MIME type is stored verbatim at upload time. Serving such
content inline with a script-capable type lets an attacker who controls a
public/gated component execute JavaScript on the sbomify origin.

We therefore only ever render a small allowlist of inert content types inline;
everything else is forced to download as an attachment, and every response
carries ``X-Content-Type-Options: nosniff`` so browsers cannot sniff a download
back into active content.
"""

from __future__ import annotations

from django.http import HttpResponse

# Content types browsers render but that cannot execute script. Deliberately
# excludes text/html, image/svg+xml and application/xhtml+xml (all can carry
# script) and anything not on the list is served as an attachment instead.
INLINE_SAFE_CONTENT_TYPES = frozenset(
    {
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "text/plain",
    }
)

_ATTACHMENT_CONTENT_TYPE = "application/octet-stream"


def _normalize_content_type(content_type: str | None) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def _sanitize_filename(filename: str | None) -> str:
    # Django already rejects CR/LF in header values; strip quotes/newlines so the
    # value cannot break out of the quoted filename parameter.
    name = (filename or "download").replace("\r", "").replace("\n", "").replace('"', "")
    return name or "download"


def apply_safe_download_headers(
    response: HttpResponse,
    *,
    content_type: str | None,
    filename: str | None,
    inline: bool,
) -> HttpResponse:
    """Set safe Content-Type / Content-Disposition / nosniff headers on ``response``.

    ``inline`` is honoured only for inert content types; every other type is
    served as an attachment regardless of what the caller requested.
    """
    normalized = _normalize_content_type(content_type)
    serve_inline = inline and normalized in INLINE_SAFE_CONTENT_TYPES

    if serve_inline:
        response["Content-Type"] = normalized
        # Allow same-origin iframe embedding (e.g. NDA preview) for inline views.
        response["X-Frame-Options"] = "SAMEORIGIN"
        disposition = "inline"
    else:
        # As an attachment the browser downloads rather than renders the bytes, so
        # even a script-capable type is inert here; nosniff (below) blocks sniffing.
        response["Content-Type"] = normalized or _ATTACHMENT_CONTENT_TYPE
        disposition = "attachment"

    response["Content-Disposition"] = f'{disposition}; filename="{_sanitize_filename(filename)}"'
    response["X-Content-Type-Options"] = "nosniff"
    return response
