"""Synthetic key material and fixed vectors for the test suite.

Everything in this file is SYNTHETIC and exists only to exercise the library. It
is not, and never was, a real key. The value is the ASCII string
``nm-secrets-synthetic-test-key!!!`` (exactly 32 bytes), which is obviously not
random key material. It will nonetheless trip secret scanners, so these exact
values (not this file path) are allowlisted in ``.gitleaks.toml``, and the
constant carries an inline ``pragma: allowlist secret`` marker for
detect-secrets. The file itself stays scanned for any other secret.
"""

import base64

# 32 ASCII bytes. Obviously synthetic; not random, not a real key.
SYNTHETIC_KEY_BYTES = b"nm-secrets-synthetic-test-key!!!"
assert len(SYNTHETIC_KEY_BYTES) == 32

# Base64 of the above, as it would appear in NM_SECRET_KEY_<KEYID>.
SYNTHETIC_KEY_B64 = "bm0tc2VjcmV0cy1zeW50aGV0aWMtdGVzdC1rZXkhISE="  # pragma: allowlist secret

# A 16-byte key, used to prove AES-128 cannot slip through under an aes256gcm
# envelope. Also synthetic.
SYNTHETIC_KEY_16_BYTES = b"sixteen-byte-key"
assert len(SYNTHETIC_KEY_16_BYTES) == 16
SYNTHETIC_KEY_16_B64 = base64.b64encode(SYNTHETIC_KEY_16_BYTES).decode("ascii")

# Fixed decryption vector. Encryption output is nondeterministic (random nonce),
# so this vector fixes the decrypt direction: decrypting VECTOR_ENVELOPE under
# the parameters below must return VECTOR_PLAINTEXT. Produced once with the
# synthetic key above.
VECTOR_NAMESPACE = "enclave"
VECTOR_KEY_ID = "gen2"
VECTOR_NAME = "db_password"
VECTOR_PLAINTEXT = "attack at dawn"
VECTOR_ENVELOPE = (
    "ENC[v1:aes256gcm:gen2:jKPVhu_OqBxDCDisjxRPA31DoCTlKIccQ5a4xs-kJ7WvoKP3euJvl6jN]"
)
