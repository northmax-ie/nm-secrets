"""Rotation across key IDs and backend IDs."""

from nm_secrets import AES256GCMBackend, EnvironmentKeyProvider, SecretHandler
from nm_secrets import envelope as envelope_module

from .helpers import CURRENT_KEY_ID, OLD_KEY_ID, RelabeledBackend, retarget


def _handler(current_key_id, current_backend_id="aes256gcm", backends=None):
    if backends is None:
        backends = [AES256GCMBackend(EnvironmentKeyProvider())]
    return SecretHandler(
        namespace="enclave",
        backends=backends,
        current_backend_id=current_backend_id,
        current_key_id=current_key_id,
    )


def test_old_key_values_remain_decryptable(env_keys):
    writer = _handler(current_key_id=OLD_KEY_ID)
    envelope = writer.encrypt("legacy value", name="db_password")
    reader = _handler(current_key_id=CURRENT_KEY_ID)
    assert reader.decrypt(envelope, name="db_password") == "legacy value"


def test_reencrypt_moves_value_to_current_key(env_keys):
    writer = _handler(current_key_id=OLD_KEY_ID)
    old_envelope = writer.encrypt("legacy value", name="db_password")

    handler = _handler(current_key_id=CURRENT_KEY_ID)
    new_envelope = handler.reencrypt(old_envelope, name="db_password")

    assert envelope_module.parse(new_envelope).key_id == CURRENT_KEY_ID
    assert handler.decrypt(new_envelope, name="db_password") == "legacy value"


def test_reencrypt_moves_value_to_current_backend(env_keys):
    provider = EnvironmentKeyProvider()
    primary = AES256GCMBackend(provider)
    secondary = RelabeledBackend(primary, "altbackend")
    backends = [primary, secondary]

    writer = _handler(
        current_key_id=CURRENT_KEY_ID,
        current_backend_id="altbackend",
        backends=backends,
    )
    old_envelope = writer.encrypt("value", name="db_password")
    assert envelope_module.parse(old_envelope).backend_id == "altbackend"

    handler = _handler(
        current_key_id=CURRENT_KEY_ID,
        current_backend_id="aes256gcm",
        backends=backends,
    )
    new_envelope = handler.reencrypt(old_envelope, name="db_password")
    assert envelope_module.parse(new_envelope).backend_id == "aes256gcm"
    assert handler.decrypt(new_envelope, name="db_password") == "value"


def test_requires_reencryption_truth_table(env_keys):
    handler = _handler(current_key_id=CURRENT_KEY_ID)

    matching = handler.encrypt("value", name="db_password")
    assert handler.requires_reencryption(matching) is False

    differing_key = _handler(current_key_id=OLD_KEY_ID).encrypt("value", name="db_password")
    assert handler.requires_reencryption(differing_key) is True

    differing_version = "ENC[v2:aes256gcm:gen2:opaque]"
    assert handler.requires_reencryption(differing_version) is True

    differing_backend = retarget(matching, backend_id="altbackend")
    assert handler.requires_reencryption(differing_backend) is True
