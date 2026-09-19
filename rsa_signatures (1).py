"""
RSA-2048 Key Pair Generation & Digital Signature Verification
-----------------------------------------------------------------
Demonstrates:
  - Generating a secure RSA-2048 public/private key pair
  - Signing a message with the private key using RSA-PSS padding
    and SHA-256 (the modern, recommended RSA signature scheme)
  - Verifying a signature with the public key
  - Detecting tampered messages / forged signatures

Requires: pip install cryptography
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def generate_rsa_keypair():
    """Generate a 2048-bit RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # standard, secure public exponent
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key, message: bytes) -> bytes:
    """Sign a message using RSA-PSS padding with SHA-256."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """
    Verify an RSA-PSS/SHA-256 signature.
    Returns True if valid, False if invalid (tampered/forged).
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def export_keys_pem(private_key, public_key):
    """Export keys in PEM format (private key unencrypted here for demo -
    in production always encrypt the private key with a passphrase)."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def demo():
    print("=== RSA-2048 Key Generation & Digital Signature Demo ===\n")

    # 1. Generate key pair
    private_key, public_key = generate_rsa_keypair()
    private_pem, public_pem = export_keys_pem(private_key, public_key)
    print("Generated RSA-2048 key pair.")
    print("\n--- Public Key (PEM) ---")
    print(public_pem.decode())

    # 2. Sign a message
    message = b"This document is authentic and issued by Siddharth G."
    signature = sign_message(private_key, message)
    print(f"Original message: {message}")
    print(f"Signature (hex, first 32 bytes shown): {signature[:32].hex()}...")

    # 3. Verify the signature
    is_valid = verify_signature(public_key, message, signature)
    print(f"\nSignature valid for original message: {is_valid}")
    assert is_valid

    # 4. Demonstrate tamper detection
    print("\n--- Tamper detection demo ---")
    tampered_message = b"This document is authentic and issued by an ATTACKER."
    is_valid_tampered = verify_signature(public_key, tampered_message, signature)
    print(f"Signature valid for TAMPERED message: {is_valid_tampered}")
    assert not is_valid_tampered
    print("Tampering correctly detected: signature verification failed as expected.")


if __name__ == "__main__":
    demo()
