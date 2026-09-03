# Using nm-secrets

How to consume the library correctly. The contract itself is in
[format-v1.md](format-v1.md) and [backend-aes256gcm.md](backend-aes256gcm.md);
the reasoning behind the design is in [design.md](design.md).

## Constructing a handler

```python
from nm_secrets import SecretHandler, AES256GCMBackend, EnvironmentKeyProvider

handler = SecretHandler(
    namespace="exampleapp",
    backends=[AES256GCMBackend(EnvironmentKeyProvider())],
    current_key_id="gen1",
)
```

- `backends` is an iterable. The handler keys backends internally by each
  backend's self-reported `backend_id`. Because the caller never supplies the map
  key, it cannot disagree with the identifier a backend stamps into an envelope,
  and a duplicate `backend_id` is rejected at construction.
- `current_backend_id` may be omitted when exactly one backend is registered, in
  which case that backend is current; it is required when several are registered.
  The handler accepts multiple backends so existing envelopes can remain readable
  while a different backend becomes current.
- `current_key_id` is validated at construction.
- New values use the current backend and key. Old envelopes select their own
  backend from the map by the `backend_id` they carry.

## Providers and backends

A `KeyProvider` resolves a key ID to raw key material and is constructed into a
local cipher backend, for example `AES256GCMBackend(provider)`. A service that
encrypts on your behalf (Vault Transit, cloud KMS, an HSM-backed service) is a
backend, not a provider, and has no provider at all. The reasoning is in
[design.md](design.md#why-key-providers-sit-behind-local-backends).

## Environment key provider

`EnvironmentKeyProvider` reads `NM_SECRET_KEY_<KEYID>`, where `<KEYID>` is the key
ID uppercased with no other transformation. The value is Base64-encoded key
material that must decode to exactly 32 bytes.

```
NM_SECRET_KEY_GEN1=<base64 of 32 random bytes>
```

Several variables may be present at once. This is required: old key IDs must stay
resolvable so values encrypted under them remain decryptable during and after
rotation.

### Key-ID naming

A key ID is an identity, not a role, so avoid names like `primary` or `current`
that go stale the moment you rotate; which key is current already lives in
`NM_SECRETS_CURRENT_KEY_ID`. Avoid a `key` prefix too, since the variable prefix
already carries it. A simple generation counter such as `gen1`, `gen2` works
well.

### Which key is current

The provider does not decide which key is current. Applications read
`NM_SECRETS_CURRENT_KEY_ID` and pass it to the handler constructor as
`current_key_id`. This library does not implement that convention; the calling
application does.

## Rotation

- Encrypt with the current backend and key ID.
- Decrypt with the backend ID and key ID carried in the envelope.
- Never trial-and-error across keys or backends. An unconfigured key ID or
  backend ID is a configuration error, not a value to be guessed past.

A store containing values under several key IDs or backend IDs is a valid state,
not corruption. Rotation is resumable and interruptible by design.

Do not remove old key material until re-encryption is complete and verified:
`reencrypt` needs the old key to resolve and the old backend to be in the map.

## Re-encryption and renaming

`reencrypt(envelope, name)` moves a value to the current backend and key. It is
the caller-composed `encrypt(decrypt(envelope, name), name)` with `name` given
once; a single argument eliminates the decrypt/encrypt name mismatch that two
names would allow, which would otherwise surface only on the next read.

Renaming a secret is a separate, caller-managed two-name migration: decrypt under
the old name, then encrypt under the new one. `reencrypt` deliberately does not
rename, and must never take an `old_name`/`new_name` pair.

Renaming a namespace or a secret name intentionally makes existing values
undecryptable. That is the AAD binding working as designed; migration is a
deliberate decrypt-then-encrypt performed by the caller.

## Declaring secret names

Declare secret names in one place (constants, an enum) rather than passing
free-form strings at call sites. The secret name feeds the AAD, so a typo is not
caught at startup; it becomes a runtime decryption failure against otherwise
valid ciphertext.
