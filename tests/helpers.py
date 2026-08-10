"""Test-configuration constants and small helpers shared across test modules."""

import base64

from nm_secrets import envelope as envelope_module

CURRENT_KEY_ID = "gen2"
OLD_KEY_ID = "gen1"
SHORT_KEY_ID = "short16"


def b64_of_32(seed: bytes) -> str:
    """Return Base64 of a deterministic 32-byte value derived from ``seed``."""
    material = (seed * 32)[:32]
    return base64.b64encode(material).decode("ascii")


def retarget(envelope: str, *, version=None, backend_id=None, key_id=None) -> str:
    """Rebuild ``envelope`` with one structural field swapped, payload intact.

    Parses the envelope and reassembles it, so only the named field changes. This
    replaces string ``.replace()`` in tests, which rewrites every occurrence and
    would corrupt the payload if the Base64 happened to contain the identifier.
    """
    parsed = envelope_module.parse(envelope)
    return "ENC[{}:{}:{}:{}]".format(
        version if version is not None else parsed.version,
        backend_id if backend_id is not None else parsed.backend_id,
        key_id if key_id is not None else parsed.key_id,
        parsed.payload,
    )


class RelabeledBackend:
    """Wraps a backend and reports a different ``backend_id``.

    The crypto is identical to the wrapped backend; only the identifier differs.
    It gives the suite a second, distinct backend ID so backend dispatch,
    AAD backend-ID binding, and re-encryption across backends can be exercised
    without inventing a second real algorithm.
    """

    def __init__(self, inner, backend_id: str) -> None:
        self._inner = inner
        self._backend_id = backend_id

    @property
    def backend_id(self) -> str:
        return self._backend_id

    def encrypt(self, plaintext: bytes, *, key_id: str, aad: bytes) -> str:
        return self._inner.encrypt(plaintext, key_id=key_id, aad=aad)

    def decrypt(self, payload: str, *, key_id: str, aad: bytes) -> bytes:
        return self._inner.decrypt(payload, key_id=key_id, aad=aad)
