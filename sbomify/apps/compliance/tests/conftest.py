"""Shared fixtures for compliance tests."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest


def mock_identity_token(identity: str, issuer: str):
    """Build a minimal OIDC token duck-typed to the sigstore
    ``IdentityToken`` surface the signer reads (``.identity``,
    ``.issuer``). Kept free of ``sigstore.oidc.IdentityToken`` so
    tests don't break when sigstore ships a minor release that
    tweaks that class's other attributes.
    """
    return type("MockIdentityToken", (), {"identity": identity, "issuer": issuer})()


@contextmanager
def mock_sigstore_signer(*, bundle_json: str = '{"ok":1}', log_index: str = "42"):
    """Patch the sigstore 4.2 signing chain end-to-end:

    ``ClientTrustConfig.production()`` → trust_config
    → ``SigningContext.from_trust_config(trust_config)`` → ctx
    → ``ctx.signer(token)`` → signer (context manager)
    → ``signer.sign_artifact(bytes)`` → bundle

    Real ``Bundle.log_entry.log_index`` is a ``str`` in the pydantic
    model; the signer does ``int(...)``. Default keeps the str shape
    to exercise that coercion path.

    Yields a dict of the mocks so call-args can be asserted.
    """
    mock_bundle = MagicMock()
    mock_bundle.to_json.return_value = bundle_json
    mock_bundle.log_entry.log_index = log_index

    mock_signer = MagicMock()
    mock_signer.sign_artifact.return_value = mock_bundle

    mock_ctx = MagicMock()
    mock_ctx.signer.return_value.__enter__.return_value = mock_signer

    mock_trust_config = MagicMock(name="ClientTrustConfig.production()")

    with patch("sigstore.models.ClientTrustConfig") as trust_cls, patch(
        "sigstore.sign.SigningContext"
    ) as ctx_cls:
        trust_cls.production.return_value = mock_trust_config
        ctx_cls.from_trust_config.return_value = mock_ctx
        yield {
            "trust_cls": trust_cls,
            "trust_config": mock_trust_config,
            "ctx_cls": ctx_cls,
            "ctx": mock_ctx,
            "signer": mock_signer,
            "bundle": mock_bundle,
        }


@pytest.fixture
def mock_s3_client():
    """Patch ``boto3.client`` and yield the mocked S3 instance.

    ``get_download_url`` does ``import boto3`` inside the function
    body then calls ``boto3.client("s3", ...)``; patching
    ``boto3.client`` at module level intercepts that call because the
    local import resolves to the same module object. The fixture
    pre-configures ``generate_presigned_url`` with a stable URL so
    tests that only care about call-args don't need to set it
    themselves.
    """
    with patch("boto3.client") as mock_client_fn:
        mock_s3 = MagicMock()
        mock_s3.generate_presigned_url.return_value = "https://s3.example.com/presigned"
        mock_client_fn.return_value = mock_s3
        yield mock_s3
