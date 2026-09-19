# Cryptography, Key Management & Secure Authentication Toolkit

A collection of Python scripts demonstrating secure cryptographic
protocols, built for the RabTech Academy Cybersecurity & Ethical
Hacking Internship (Milestone 05).

## Contents

| File | Demonstrates |
|---|---|
| `aes_gcm_encryption.py` | AES-256-GCM authenticated symmetric encryption/decryption with random IVs |
| `rsa_signatures.py` | RSA-2048 key pair generation and digital signature verification (RSA-PSS + SHA-256) |
| `password_hashing.py` | Secure password hashing and verification using bcrypt (salting + configurable work factor) |
| `hmac_integrity.py` | HMAC-SHA256 message integrity/authenticity verification |

## Requirements

```bash
pip install cryptography bcrypt
```

## Running the demos

Each script is self-contained and can be run directly to see a
worked demonstration, including a deliberate "tamper detection" test
proving that any modification to ciphertext/messages/signatures is
correctly rejected:

```bash
python3 aes_gcm_encryption.py
python3 rsa_signatures.py
python3 password_hashing.py
python3 hmac_integrity.py
```

---

## Security Best Practices: Secret & Key Storage, Rotation

### 1. Key/Secret Generation
- Always generate keys using a cryptographically secure random
  number generator (`os.urandom`, or a library's dedicated key-gen
  function like `AESGCM.generate_key()` / `rsa.generate_private_key()`).
  **Never** derive keys from predictable sources (timestamps,
  usernames, weak passwords) without a proper KDF.
- Use industry-standard key sizes: AES-256 (32-byte key), RSA-2048
  minimum (RSA-3072/4096 for longer-term protection), HMAC keys of
  at least 256 bits.

### 2. Never Hard-Code Secrets
- Do not commit API keys, passwords, or private keys to source
  control (as this repository's `.gitignore` reflects). Use
  environment variables, `.env` files (excluded from git), or a
  dedicated secrets manager.
- Recommended production tools: **AWS KMS / Secrets Manager**,
  **HashiCorp Vault**, **Azure Key Vault**, **Google Cloud KMS**.
  These provide encryption-at-rest for secrets, fine-grained access
  control, and audit logging of every access.

### 3. Encryption Keys vs. Data
- Keys used to encrypt data should themselves be encrypted at rest
  ("envelope encryption") using a separate master key held in a
  hardware security module (HSM) or KMS, so that compromising the
  database alone does not expose the data-encryption keys.

### 4. Nonce/IV Management (AES-GCM)
- A `(key, nonce)` pair must **never** be reused. Reusing a nonce
  with the same key in GCM mode catastrophically breaks
  confidentiality and authenticity. Always generate a fresh random
  96-bit nonce per encryption operation (as done in
  `aes_gcm_encryption.py`), or use a strictly monotonic counter if
  randomness cannot be guaranteed unique at sufficient scale.

### 5. Password Storage
- Never store plaintext passwords or use fast general-purpose
  hashes (MD5, SHA-1, plain SHA-256) for passwords.
- Use a slow, salted, tunable algorithm: **bcrypt**, **scrypt**, or
  **Argon2id** (Argon2id is the current OWASP-recommended default
  where available).
- Increase the work factor (bcrypt `rounds`) periodically as
  hardware gets faster, and support re-hashing existing password
  hashes transparently at next login when the cost factor changes.

### 6. Digital Signatures
- Use RSA-PSS (not the legacy PKCS#1 v1.5 padding) with SHA-256 or
  stronger for new RSA signature schemes, or prefer elliptic-curve
  signatures (Ed25519 / ECDSA P-256) for smaller keys and faster
  operations at equivalent security levels.
- Private keys used for signing must be stored encrypted at rest
  and access-controlled; a compromised signing key allows an
  attacker to forge signatures indefinitely until the key is
  revoked/rotated.

### 7. Key Rotation
- Define a rotation policy per key type:
  - **Symmetric data-encryption keys:** rotate periodically (e.g.
    annually, or immediately on suspected compromise); re-encrypt
    data with the new key or maintain a versioned key registry so
    old ciphertext can still be decrypted with the correct
    historical key.
  - **RSA/signing keys:** rotate on a defined schedule (e.g. every
    1-2 years) and immediately upon suspected compromise; maintain
    key IDs so verifiers can select the correct historical public
    key for older signatures.
  - **Password hashes:** re-hash on next successful login if the
    work factor has increased since the hash was created.
- Maintain a key version/ID alongside encrypted data or signatures
  so that rotation does not break the ability to decrypt/verify
  older data.

### 8. General
- Prefer well-reviewed, actively maintained cryptography libraries
  (Python's `cryptography` package, `bcrypt`) over hand-rolled
  implementations of cryptographic primitives.
- Always verify authentication tags/signatures fully before trusting
  or using decrypted data — never "decrypt first, check later."
- Use constant-time comparison functions (e.g. `hmac.compare_digest`)
  for any secret comparison to avoid timing side-channel attacks.

---

*This toolkit was built for educational purposes to demonstrate secure
cryptographic implementation patterns as part of a cybersecurity
internship curriculum.*
