"""Envelope parsing: wrapper syntax only."""

import pytest

from nm_secrets import Envelope, SecretFormatError
from nm_secrets import envelope as envelope_module

UNSUPPORTED = "ENC[v2:aes256gcm:gen2:someopaquepayload]"


def test_payload_containing_colons_recovered_whole():
    parsed = envelope_module.parse("ENC[v1:aes256gcm:key_1:aa:bb:cc]")
    assert isinstance(parsed, Envelope)
    assert parsed.payload == "aa:bb:cc"


def test_payload_containing_bracket_recovered_whole():
    parsed = envelope_module.parse("ENC[v1:aes256gcm:key_1:pay]load]")
    assert parsed.payload == "pay]load"


def test_missing_prefix_raises():
    with pytest.raises(SecretFormatError):
        envelope_module.parse("v1:aes256gcm:key_1:payload]")


def test_missing_terminator_raises():
    with pytest.raises(SecretFormatError):
        envelope_module.parse("ENC[v1:aes256gcm:key_1:payload")


def test_too_few_components_raises():
    with pytest.raises(SecretFormatError):
        envelope_module.parse("ENC[v1:aes256gcm:key_1]")


def test_unsupported_version_parses_successfully():
    parsed = envelope_module.parse(UNSUPPORTED)
    assert parsed.version == "v2"
    assert parsed.backend_id == "aes256gcm"
    assert parsed.payload == "someopaquepayload"


def test_requires_reencryption_true_on_unsupported_version(handler):
    assert handler.requires_reencryption(UNSUPPORTED) is True


def test_decrypt_raises_on_unsupported_version(handler):
    with pytest.raises(SecretFormatError):
        handler.decrypt(UNSUPPORTED, name="db_password")


def test_reencrypt_raises_on_unsupported_version(handler):
    with pytest.raises(SecretFormatError):
        handler.reencrypt(UNSUPPORTED, name="db_password")


def test_requires_reencryption_raises_on_invalid_envelope(handler):
    with pytest.raises(SecretFormatError):
        handler.requires_reencryption("not an envelope at all")


def test_requires_reencryption_true_on_v2_structured_envelope(handler):
    # A future version may abandon the v1 four-part structure. Version discovery
    # alone must still answer True, without the v1 grammar being satisfiable.
    assert handler.requires_reencryption("ENC[v2:some-entirely-new-shape]") is True


def test_requires_reencryption_rejects_over_length_envelope(handler):
    with pytest.raises(SecretFormatError):
        handler.requires_reencryption("ENC[" + "A" * 90001 + "]")


def test_requires_reencryption_rejects_missing_version_delimiter(handler):
    with pytest.raises(SecretFormatError):
        handler.requires_reencryption("ENC[nodelimiter]")


def test_requires_reencryption_rejects_empty_version(handler):
    # ``ENC[:whatever]`` has a delimiter but no version: malformed, not a future
    # version.
    with pytest.raises(SecretFormatError):
        handler.requires_reencryption("ENC[:whatever]")


@pytest.mark.parametrize(
    "envelope",
    [
        "ENC[v1:aes256gcm:gen2\n:payload]",
        "ENC[v1:aes256gcm\n:gen2:payload]",
    ],
)
def test_trailing_newline_in_identifier_rejected(envelope):
    # ``$`` matches before a final newline, so ``.match()`` would admit these;
    # ``.fullmatch()`` rejects them, keeping the frozen grammar frozen.
    with pytest.raises(SecretFormatError):
        envelope_module.parse(envelope)
