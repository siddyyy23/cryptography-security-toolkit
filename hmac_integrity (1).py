"""
HMAC (Hash-based Message Authentication Code) Demo
------------------------------------------------------
Demonstrates using HMAC-SHA256 to verify the integrity and
authenticity of a message using a shared secret key. Unlike a plain
hash (e.g. SHA-256 of the message alone), HMAC requires knowledge of
the secret key to produce a valid tag, so an attacker who intercepts
and modifies the message cannot forge a matching HMAC without the key.

Common uses: verifying webhook payloads, API request signing,
integrity-checking config/data files, JWT signing (HS256).

Requires: pip install cryptography
"""

import os
import hmac as hmac_lib
import hashlib


def generate_hmac_key() -> bytes:
    """Generate a cryptographically secure random 256-bit HMAC key."""
    return os.urandom(32)


def compute_hmac(message: bytes, key: bytes) -> bytes:
    """Compute an HMAC-SHA256 tag for a message using the shared secret key."""
    return hmac_lib.new(key, message, hashlib.sha256).digest()


def verify_hmac(message: bytes, key: bytes, received_tag: bytes) -> bool:
    """
    Verify an HMAC-SHA256 tag using a constant-time comparison
    (hmac.compare_digest) to prevent timing attacks that could
    otherwise leak information about the correct tag byte-by-byte.
    """
    expected_tag = compute_hmac(message, key)
    return hmac_lib.compare_digest(expected_tag, received_tag)


def demo():
    print("=== HMAC-SHA256 Message Integrity & Authenticity Demo ===\n")

    key = generate_hmac_key()
    print(f"Shared secret key (hex): {key.hex()}")

    message = b'{"amount": 500, "to_account": "ACC-1001"}'
    tag = compute_hmac(message, key)
    print(f"\nMessage: {message}")
    print(f"HMAC-SHA256 tag: {tag.hex()}")

    # Verify an untampered message
    ok = verify_hmac(message, key, tag)
    print(f"\nVerification of ORIGINAL message: {ok}")
    assert ok

    # Demonstrate tamper detection - attacker changes the amount
    tampered_message = b'{"amount": 999999, "to_account": "ACC-1001"}'
    tampered_ok = verify_hmac(tampered_message, key, tag)
    print(f"Verification of TAMPERED message (same tag): {tampered_ok}")
    assert not tampered_ok
    print("Tampering correctly detected: HMAC verification failed as expected.")

    # Demonstrate why constant-time comparison matters
    print("\nNote: verification uses hmac.compare_digest() rather than '==' "
          "to avoid timing side-channel attacks that could let an attacker "
          "guess the correct tag one byte at a time.")


if __name__ == "__main__":
    demo()
