"""Associated data: binds a ciphertext to its full identity.

Built here, not in a backend, so a backend cannot vary its composition. Fields
in fixed order: version, backend ID, key ID, namespace, secret name. Each is
length-prefixed (4-byte big-endian length + UTF-8 bytes); without the prefixes
``namespace="ab", name="c"`` and ``namespace="a", name="bc"`` would collide.
"""

import struct

_LENGTH_PREFIX = ">I"  # 4-byte big-endian unsigned length


def _field(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(_LENGTH_PREFIX, len(encoded)) + encoded


def build_aad(
    version: str,
    backend_id: str,
    key_id: str,
    namespace: str,
    name: str,
) -> bytes:
    """Return the length-prefixed AAD for the given identity fields."""
    return b"".join(
        (
            _field(version),
            _field(backend_id),
            _field(key_id),
            _field(namespace),
            _field(name),
        )
    )
