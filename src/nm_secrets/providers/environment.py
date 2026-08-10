"""Environment-variable key provider.

Reads ``NM_SECRET_KEY_<KEYID>`` (key ID uppercased), a Base64 value that must
decode to exactly 32 bytes. Several may be set at once so old key IDs stay
resolvable during rotation; this provider does not decide which key is current.
"""

import base64
import binascii
import os

from ..exceptions import SecretConfigurationError

_ENV_PREFIX = "NM_SECRET_KEY_"
_KEY_BYTES = 32


class EnvironmentKeyProvider:
    """Resolves key IDs against ``NM_SECRET_KEY_<KEYID>`` environment variables."""

    def get_key(self, key_id: str) -> bytes:
        # Every message names the key ID only, never the material.
        var = _ENV_PREFIX + key_id.upper()
        raw = os.environ.get(var)
        if raw is None:
            raise SecretConfigurationError(
                f"no key material for key_id {key_id!r}"
            ) from None

        try:
            material = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            raise SecretConfigurationError(
                f"key material for key_id {key_id!r} is not valid Base64"
            ) from None

        if len(material) != _KEY_BYTES:
            raise SecretConfigurationError(
                f"key material for key_id {key_id!r} is not {_KEY_BYTES} bytes"
            ) from None

        return material
