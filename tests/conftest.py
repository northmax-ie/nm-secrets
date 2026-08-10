"""Shared fixtures.

Key material is injected through the environment, as the real
``EnvironmentKeyProvider`` reads it, so tests exercise the provider end to end.
All key material here is synthetic; see ``synthetic_key_material``.
"""

import pytest

from nm_secrets import AES256GCMBackend, EnvironmentKeyProvider, SecretHandler

from .helpers import CURRENT_KEY_ID, OLD_KEY_ID, SHORT_KEY_ID, b64_of_32
from .synthetic_key_material import (
    SYNTHETIC_KEY_16_B64,
    SYNTHETIC_KEY_B64,
    VECTOR_NAMESPACE,
)


@pytest.fixture
def env_keys(monkeypatch):
    """Populate NM_SECRET_KEY_* with synthetic material for several key IDs."""
    monkeypatch.setenv(f"NM_SECRET_KEY_{CURRENT_KEY_ID.upper()}", SYNTHETIC_KEY_B64)
    monkeypatch.setenv(f"NM_SECRET_KEY_{OLD_KEY_ID.upper()}", b64_of_32(b"old"))
    monkeypatch.setenv(f"NM_SECRET_KEY_{SHORT_KEY_ID.upper()}", SYNTHETIC_KEY_16_B64)
    return monkeypatch


@pytest.fixture
def provider(env_keys):
    return EnvironmentKeyProvider()


@pytest.fixture
def backend(provider):
    return AES256GCMBackend(provider)


@pytest.fixture
def handler(backend):
    """A handler in namespace 'enclave' on the current backend and key."""
    # current_backend_id omitted on purpose: with one backend it defaults to
    # that backend, which is the common single-backend ergonomic path.
    return SecretHandler(
        namespace=VECTOR_NAMESPACE,
        backends=[backend],
        current_key_id=CURRENT_KEY_ID,
    )
