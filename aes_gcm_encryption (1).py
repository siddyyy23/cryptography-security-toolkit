"""
AES-256-GCM Authenticated Encryption / Decryption
---------------------------------------------------
Demonstrates secure symmetric encryption using AES in GCM mode
(Galois/Counter Mode), which provides both confidentiality AND
integrity/authenticity (AEAD - Authenticated Encryption with
Associated Data).

Key security practices demonstrated:
  - 256-bit (32-byte) key, generated with a CSPRNG (os.urandom)
  - A fresh, random 96-bit (12-byte) IV/nonce for every encryption
    operation (NEVER reuse an IV with the same key in GCM mode)
  - The authentication tag is verified automatically on decrypt;
    any tampering with ciphertext raises InvalidTag
  - Optional "associated data" (AAD) can be authenticated without
    being encrypted (e.g. a header or metadata field)

Requires: pip install cryptography
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    """Generate a cryptographically secure random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.

    Returns:
        (nonce, ciphertext) - the nonce must be stored/transmitted
        alongside the ciphertext (it is not secret) so it can be
        used during decryption. The ciphertext already includes
        the authentication tag appended at the end.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce, freshly generated every time
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.

    Raises cryptography.exceptions.InvalidTag if the ciphertext
    or associated data has been tampered with, or if the wrong
    key/nonce is used.
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext


def demo():
    print("=== AES-256-GCM Authenticated Encryption Demo ===\n")

    # 1. Generate a random 256-bit key (in production, store this
    #    in a secrets manager / KMS, never hard-code it)
    key = generate_key()
    print(f"Generated 256-bit key (hex): {key.hex()}")

    # 2. Encrypt a message
    message = b"This is a confidential message protected by AES-256-GCM."
    aad = b"header:user-id=1234"  # authenticated but not encrypted
    nonce, ciphertext = encrypt(message, key, associated_data=aad)

    print(f"\nOriginal plaintext : {message}")
    print(f"Nonce (12 bytes)    : {nonce.hex()}")
    print(f"Ciphertext (+ tag)  : {ciphertext.hex()}")

    # 3. Decrypt and verify
    decrypted = decrypt(nonce, ciphertext, key, associated_data=aad)
    print(f"\nDecrypted plaintext : {decrypted}")
    assert decrypted == message
    print("Integrity check passed: decrypted plaintext matches original.")

    # 4. Demonstrate tamper detection
    print("\n--- Tamper detection demo ---")
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # flip bits in the first byte
    try:
        decrypt(nonce, bytes(tampered_ciphertext), key, associated_data=aad)
        print("ERROR: tampering was not detected!")
    except Exception as e:
        print(f"Tampering correctly detected and rejected: {type(e).__name__}")


if __name__ == "__main__":
    demo()
