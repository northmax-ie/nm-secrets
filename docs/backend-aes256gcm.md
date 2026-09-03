# Backend payload specification: aes256gcm

This document specifies the **payload layer** for the `aes256gcm` backend: what
this backend places inside the opaque payload of a `v1` envelope. The envelope
wrapper is specified separately in [format-v1.md](format-v1.md).

A backend ID identifies a **payload interpretation**, not merely a primitive. A
changed payload layout is a new backend ID, never a redefinition of this one.

## Payload layout

```
payload = urlsafe_base64(nonce || ciphertext || tag)
```

The three parts are concatenated in that order, then Base64-encoded as a single
string.

## Algorithm and parameters

- AES-256-GCM via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. No
  primitive is implemented in this repository; every operation routes through
  `cryptography`.
- **Key**: exactly 32 bytes. `AESGCM` also accepts 128- and 192-bit keys, so the
  backend rejects any key that is not 32 bytes rather than silently producing
  AES-128-GCM under an envelope reading `aes256gcm`.
- **Nonce**: 12 bytes from `os.urandom`, independently generated for every
  encryption. Nonce reuse with the same key is forbidden; the per-key operation
  limit below bounds the collision risk. No method accepts a nonce, IV, or other
  randomness as a parameter, because a parameter is the mechanism by which nonce
  reuse happens.
- **Tag**: 16 bytes, the GCM default, appended by `AESGCM.encrypt` and carried at
  the end of the pre-Base64 byte string.
- **AAD**: the `aad` bytes supplied by the envelope layer are passed unchanged as
  the associated data to `AESGCM.encrypt` and `AESGCM.decrypt`. The backend does
  not construct, extend, or interpret it.

## Operation limit

Limited to at most `2^32` encryption operations across all uses of a given key,
per the selected random-IV construction (NIST SP 800-38D). Replace the key
material before approaching this bound; for this local backend, rotation assigns
fresh key material under a new key ID.

## Base64 rules

- **Encode** with `base64.urlsafe_b64encode`.
- **Decode** with `base64.b64decode(s, altchars=b"-_", validate=True)`.
  `base64.urlsafe_b64decode` has no `validate` parameter, and Python's
  non-strict mode discards non-alphabet characters before checking padding, so a
  payload containing stray non-alphabet characters would decode silently.
- **Padding is retained**, so decode is one call with no reconstruction step.

Base64 is a property of this backend's payload, not of the envelope.

## Failure classification

- A payload that is not valid strict Base64, or that is too short to contain a
  nonce and tag, is a `SecretFormatError`.
- A failed authentication (for example, wrong key, wrong AAD/context, or
  tampering) is a `SecretDecryptionError`, and nothing else is classified there.
- Key material that is not a 32-byte `bytes` value (wrong length, or not `bytes`
  at all) is a `SecretConfigurationError`, so a defective provider cannot leak a
  raw `TypeError` from the primitive.
