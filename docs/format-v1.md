# Envelope format v1

This document specifies the **envelope layer**: the wrapper around a backend
payload. The payload is an **opaque string** throughout this document. What a
given backend puts inside the payload is a separate specification; for
`aes256gcm` see [backend-aes256gcm.md](backend-aes256gcm.md).

A `v1` envelope does not imply an AES-GCM payload. A future Vault Transit backend
could produce a `v1` envelope carrying a Vault-shaped payload. The envelope
version and the payload interpretation are independent.

## Grammar

```
ENC[<version>:<backend_id>:<key_id>:<payload>]
```

## Version discovery is frozen permanently

Across all envelope versions, forever, an envelope is discoverable when it
satisfies four requirements: it begins with `ENC[`, its final character is `]`,
a first `:` is present, and the version (the text between `ENC[` and that first
`:`) is non-empty. A parser of any vintage can discover the version of any
discoverable envelope.

This is the minimum that supports `requires_reencryption` on an envelope written
by a newer package: a version mismatch alone is sufficient to return `True`, so
no other field needs to be readable.

The remainder of the grammar is frozen for **v1 only**. A future version may
define a different internal structure after the version field. It must not
redefine v1.

## Parsing rule, v1

- Verify the `ENC[` prefix and the terminating final character `]`.
- Strip both, then split the remainder on `:` with **at most three splits**.
- The payload is the entire remaining string. **It may contain colons, and it
  may contain `]`.** Only the final character terminates the envelope.

An unbounded `split(":")` silently requires a colon-free payload. That holds for
`aes256gcm` and would break on the first opaque remote-backend payload, so it is
not permitted.

## Parsing versus interpretation

Two distinct operations exist, and they must not be conflated:

**Version discovery** follows the permanently frozen rules above and does not
validate version-specific structure. `requires_reencryption` uses it: a
non-discoverable value raises `SecretFormatError`; a discoverable envelope whose
version differs from the current one returns `True` immediately.

**`parse(value)` is the v1 wrapper parser.** It validates the prefix and
terminator, the split arity, the identifier grammars, and the envelope length,
and returns a named structured type with `version`, `backend_id`, `key_id` and
`payload`. It does not require the version to be *supported*, but it does require
the **v1 four-part structure**, so it is meaningful only for values that carry
the v1 layout. A future `v2` envelope with a different internal grammar is
discoverable but not v1-parseable, and that is intended: `parse` is not the
cross-version reader, version discovery is.

Operations that **interpret** an envelope reject unsupported versions. `decrypt`
and `reencrypt` raise `SecretFormatError` on an unsupported version before
dispatching to any backend, and the raised message never echoes the version
value, which is untrusted, unbounded input.

For an envelope this package cannot read, `requires_reencryption` returns `True`
and `reencrypt` then raises: that pair tells an operator the value needs
migration and that this package version cannot perform it.

## Identifier grammar

- `key_id`: `^[a-z0-9_]{1,64}$`
- `backend_id`: `^[a-z0-9]{1,32}$`

Hyphens are excluded from `key_id` so that every valid key ID maps directly to a
conventional portable shell variable name by uppercasing only, with no
normalization or character replacement. Colons are excluded because `key_id`
sits between structural delimiters and feeds AAD construction.

Backend IDs are lowercase alphanumeric identifiers, for compact unambiguous
parsing and stable naming: `aes256gcm`, `vaulttransit`, `awskms`.

Identifiers parsed out of an envelope are validated **during parsing**, before
reaching any backend or provider. Envelope content is untrusted input; without
this, a traversal-shaped `key_id` such as `../../something` would reach a
provider unvalidated, and a future file-based or HSM-slot provider could map it
to a path or handle.

## Size limits

- **Maximum plaintext: 65536 bytes of UTF-8-encoded plaintext**, checked after
  encoding. The limit is bytes, not characters.
- **Maximum v1 envelope: 90000 characters**, checked on string length before
  v1 parsing.

Both are fixed at v1 and **not configurable**. A configurable limit lets
application A write a value application B refuses to read, which breaks the
interoperability this library exists for.

The envelope limit is a fixed v1 envelope-layer constant that every backend
producing a v1 envelope must fit within; it is not recalculated per backend. It
is enforced during v1 parsing only; version discovery never applies it, so a
value carrying an unsupported future version remains discoverable regardless of
length. The number is derived once from the largest envelope `aes256gcm` can
produce with maximum-length identifiers:

- Payload: `nonce (12) + ciphertext (65536) + tag (16) = 65564` bytes, Base64
  encoded with retained padding, is **87420 characters**.
- Wrapper: `ENC[`, `]` and three `:` delimiters add **8**; the version `v1`
  adds **2**; a maximum `backend_id` adds **32**; a maximum `key_id` adds **64**.

The maximum is therefore 87526 characters, rounded up to a fixed
**90000**-character v1 envelope limit for headroom.

## Associated data

AAD is constructed at the envelope layer. Fields, in fixed order:

1. envelope format version
2. backend ID
3. key ID
4. namespace
5. secret name

Encoding is deterministic and **length-prefixed**: for each field, a 4-byte
big-endian length followed by the UTF-8 bytes. Without length prefixes,
`namespace="ab", name="c"` and `namespace="a", name="bc"` produce identical AAD
and become cross-decryptable.

Backends receive `aad` as an opaque parameter and cannot vary its composition.

Namespace is fixed at handler construction. Secret name is passed per call and is
not recoverable from the envelope, which is what makes relocating a ciphertext
from one slot to another fail. Renaming a namespace or secret name intentionally
makes existing values undecryptable; migration is decrypt under the old name,
encrypt under the new, performed deliberately by the caller.

Key separation is the isolation boundary between applications. Namespace in AAD
is defence in depth. Two applications must never share key material on the
grounds that their namespaces differ.

## Key ID semantics across backend classes

- **Local backends** (`aes256gcm`): `key_id` identifies actual key material.
  Rotation changes it, and therefore changes the AAD, so rotation requires
  decrypt-then-encrypt.
- **Remote backends** (Vault Transit, cloud KMS): `key_id` maps to the **stable
  remote key name**, never a name-plus-version composite. The version lives
  inside the service's opaque ciphertext, so the service can rewrap to a new key
  version without the envelope or AAD changing. A name-plus-version mapping would
  foreclose rewrap.

`key_id` is an **alias, not a native identifier**. The grammar cannot express
most Vault or KMS identifiers, so a remote backend owns its own mapping table
from `key_id` to its native key reference.

## Stability

- Version discovery is frozen permanently.
- v1 semantics and grammar are frozen permanently once released. A change to any
  v1 envelope-layer semantics (the wrapper structure, identifier grammar, size
  limits, or AAD construction) is `v2`; a future version must not redefine v1.
- A changed backend payload layout is a **new backend ID**, never a redefinition
  of an existing one.
- The package never silently drops a reader for a previously released format.
  Retiring a released format requires a major package release, migration
  guidance, and a documented security rationale. Fixed test vectors are the
  enforcement mechanism.
