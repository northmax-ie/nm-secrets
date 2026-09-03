# nm-secrets

Versioned, AAD-bound encrypted envelopes for Python applications. It encrypts a
value and decrypts a value. **It does not store anything, read config, or know
what an application is.**

Input plaintext plus a secret name, output an envelope string; input an envelope
string plus a secret name, output plaintext. For local cipher backends, key
material is resolved through a provider owned by the backend.

It is a library rather than a function because of the **stored format**: several
applications must produce values that are mutually readable, rotatable, and
reviewable once. Everything not implied by the format belongs to the calling
application.

**What it is not.** Not a store or persistence layer; the caller owns where
ciphertext goes. Not config loading, YAML, or env-over-store precedence. No
plaintext passthrough; a value that is not a valid envelope is an error. No
signing, hashing, KDFs, or key caching in the shared handler; those belong to
backends, providers, or callers.

## Install

```bash
pip install nm-secrets
```

Requires Python 3.11+. Ships type information (`py.typed`). One compiled runtime
dependency, `cryptography`.

### Air-gapped install

The package supports fully offline installation. The consuming application's
release bundles a pinned version of this package plus all required wheels;
`cryptography` must be present in the offline artifact for the exact target
Python version, platform, architecture, and libc where applicable. The
`aes256gcm` backend and `EnvironmentKeyProvider` require no external service at
runtime.

```bash
# From a directory holding this package's wheel and all dependency wheels for
# the target platform:
pip install --no-index --find-links ./wheels nm-secrets
```

## Quick start

```python
from nm_secrets import SecretHandler, AES256GCMBackend, EnvironmentKeyProvider

provider = EnvironmentKeyProvider()
handler = SecretHandler(
    namespace="exampleapp",
    backends=[AES256GCMBackend(provider)],
    current_key_id="gen1",
)

envelope = handler.encrypt("s3cr3t", name="db_password")
plaintext = handler.decrypt(envelope, name="db_password")
```

Callers never touch `AESGCM` objects, nonces, tags, Base64, envelope parsing, or
AAD serialisation. See [docs/usage.md](docs/usage.md) for the backend map,
provider wiring, key-ID naming, and rotation in full.

## Guarantees

- **No plaintext passthrough.** A value that is not a valid envelope is an error.
  Migrating previously unencrypted values is the caller's job, done before this
  library is called.
- **Context binding.** Ciphertext is bound through AAD to the format version,
  backend, key ID, namespace, and secret name. Decrypting under the wrong
  namespace or secret name fails authentication, so a value cannot be relocated
  between slots.
- **Key separation is the isolation boundary between applications.** Namespace in
  the AAD is defence in depth; two applications must never share key material on
  the grounds that their namespaces differ.
- **Immutable format.** A released envelope version is immutable, and reader
  support is never dropped silently. Retiring a released format requires a major
  package release with migration guidance and a documented security rationale.
  See [CHANGELOG.md](CHANGELOG.md).
- **No primitives in-repo.** The `aes256gcm` backend routes cryptographic
  operations through `cryptography`'s `AESGCM`; nonce generation uses
  `os.urandom`. AES-256-GCM is used rather than Fernet because the format binds
  ciphertext to its namespace and secret name via AAD, which Fernet cannot
  express; full rationale in [docs/design.md](docs/design.md).

The bundled `aes256gcm` backend uses AES-256-GCM, but nm-secrets makes no claim
that installing the package by itself constitutes FIPS 140-3 validated operation.
FIPS validation is a property of the deployed cryptographic module, its
configuration, operational environment, and approved mode.

## Rotation

- New values use the current backend and key ID; old envelopes are read with the
  backend ID and key ID they carry.
- A store holding values under several key IDs or backend IDs is a valid,
  resumable state, not corruption.
- Do not remove old key material until re-encryption is complete and verified:
  `reencrypt` needs the old key to resolve and the old backend in the map.
- `reencrypt(envelope, name)` moves a value to the current backend and key. It
  takes a **single** name and deliberately does not rename; renaming a secret is
  a caller-managed two-name migration. See [docs/usage.md](docs/usage.md).

## Environment key provider

`EnvironmentKeyProvider` reads `NM_SECRET_KEY_<KEYID>`, where `<KEYID>` is the key
ID uppercased with no other transformation. The value is Base64-encoded key
material that must decode to exactly 32 bytes. Several keys may be present at once
so old key IDs stay resolvable during and after rotation.

```
NM_SECRET_KEY_GEN1=<base64 of 32 random bytes>
```

The provider does not decide which key is current; applications read
`NM_SECRETS_CURRENT_KEY_ID` and pass it to the handler. This library does not
implement that convention. See [docs/usage.md](docs/usage.md) for key-ID naming
guidance.

## Declare secret names in one place

Declare secret names centrally (constants, an enum) rather than passing free-form
strings at call sites. The secret name feeds the AAD, so a typo is not a startup
error but a runtime decryption failure. This is an application rule, but it
belongs here because this library creates the hazard.

## Documentation

The format is specified in two independent layers: the envelope wrapper and the
backend payload. **A `v1` envelope does not imply an AES-GCM payload** - a future
backend could carry a different payload inside a `v1` envelope.

- [docs/format-v1.md](docs/format-v1.md) - the envelope layer: wrapper,
  identifiers, size limits, AAD, and version rules.
- [docs/backend-aes256gcm.md](docs/backend-aes256gcm.md) - the `aes256gcm`
  payload layer: algorithm, nonce, tag, Base64, and limits.
- [docs/usage.md](docs/usage.md) - how to consume the library correctly.
- [docs/design.md](docs/design.md) - why the architecture made its choices.

`docs/format-v1.md` and the applicable backend payload specification are
normative. Any implementation or documentation that diverges from them is
defective.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT - see [LICENSE](LICENSE).
