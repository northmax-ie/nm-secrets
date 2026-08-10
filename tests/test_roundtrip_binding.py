"""Round trip and AAD binding."""

import pytest

from nm_secrets import (
    AES256GCMBackend,
    EnvironmentKeyProvider,
    SecretDecryptionError,
    SecretHandler,
)

from .helpers import CURRENT_KEY_ID, b64_of_32, retarget
from .synthetic_key_material import SYNTHETIC_KEY_B64


def _handler(namespace, backends=None, current_backend_id="aes256gcm"):
    provider = EnvironmentKeyProvider()
    if backends is None:
        backends = [AES256GCMBackend(provider)]
    return SecretHandler(
        namespace=namespace,
        backends=backends,
        current_backend_id=current_backend_id,
        current_key_id=CURRENT_KEY_ID,
    )


def test_encrypt_decrypt_round_trip(handler):
    envelope = handler.encrypt("hunter2", name="db_password")
    assert handler.decrypt(envelope, name="db_password") == "hunter2"


def test_wrong_key_fails(handler, env_keys):
    envelope = handler.encrypt("hunter2", name="db_password")
    # Same key ID now resolves to different material.
    env_keys.setenv(f"NM_SECRET_KEY_{CURRENT_KEY_ID.upper()}", b64_of_32(b"different"))
    with pytest.raises(SecretDecryptionError):
        handler.decrypt(envelope, name="db_password")


def test_wrong_namespace_fails(handler, env_keys):
    envelope = handler.encrypt("hunter2", name="db_password")
    other = _handler(namespace="somethingelse")
    with pytest.raises(SecretDecryptionError):
        other.decrypt(envelope, name="db_password")


def test_wrong_secret_name_fails(handler):
    envelope = handler.encrypt("hunter2", name="db_password")
    with pytest.raises(SecretDecryptionError):
        handler.decrypt(envelope, name="api_token")


def test_modified_key_id_in_envelope_fails(handler, env_keys):
    # Retarget to another key ID that resolves, so the failure is the AAD
    # binding rather than missing material.
    envelope = handler.encrypt("hunter2", name="db_password")
    tampered = retarget(envelope, key_id="gen1")
    with pytest.raises(SecretDecryptionError):
        handler.decrypt(tampered, name="db_password")


def test_modified_backend_id_in_envelope_fails(env_keys):
    from .helpers import RelabeledBackend

    provider = EnvironmentKeyProvider()
    primary = AES256GCMBackend(provider)
    secondary = RelabeledBackend(primary, "altbackend")
    handler = _handler(
        namespace="enclave",
        backends=[primary, secondary],
    )
    envelope = handler.encrypt("hunter2", name="db_password")
    # Both backends decrypt identically, but the AAD carries the backend ID.
    tampered = retarget(envelope, backend_id="altbackend")
    with pytest.raises(SecretDecryptionError):
        handler.decrypt(tampered, name="db_password")


def test_aad_length_prefix_ambiguity(env_keys):
    # namespace="ab", name="c" must not decrypt a value written as
    # namespace="a", name="bc".
    writer = _handler(namespace="a")
    envelope = writer.encrypt("hunter2", name="bc")
    reader = _handler(namespace="ab")
    with pytest.raises(SecretDecryptionError):
        reader.decrypt(envelope, name="c")


def test_nonce_uniqueness(handler):
    first = handler.encrypt("same plaintext", name="db_password")
    second = handler.encrypt("same plaintext", name="db_password")
    assert first != second
