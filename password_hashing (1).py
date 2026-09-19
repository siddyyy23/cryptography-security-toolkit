"""
Secure Password Hashing with bcrypt
--------------------------------------
Demonstrates secure password storage using bcrypt, which
automatically:
  - Generates a unique random salt per password (prevents rainbow
    table attacks and ensures identical passwords produce different
    hashes)
  - Applies a configurable "work factor" / cost (rounds), making
    brute-force attacks computationally expensive and allowing the
    cost to be increased over time as hardware gets faster

NEVER store passwords in plaintext, and NEVER use fast general-purpose
hash functions like MD5 or plain SHA-256 for passwords - they are
designed to be fast, which is exactly the wrong property for password
hashing (it makes brute-forcing cheap). bcrypt (or Argon2/scrypt) is
deliberately slow and tunable.

Requires: pip install bcrypt
"""

import bcrypt


def hash_password(plain_password: str, rounds: int = 12) -> bytes:
    """
    Hash a plaintext password using bcrypt.

    `rounds` controls the work factor (cost): each increment doubles
    the computation time. 12 is a reasonable default in 2026;
    increase it over time as hardware improves.
    """
    salt = bcrypt.gensalt(rounds=rounds)  # unique random salt, baked into the hash
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed


def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.
    The salt and cost factor are embedded in `hashed_password`,
    so bcrypt.checkpw handles that automatically.
    """
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password)


def demo():
    print("=== Secure Password Hashing with bcrypt Demo ===\n")

    password = "Cor rectHorseBatteryStaple!42"

    # 1. Hash the password (as you would before storing it in a DB)
    hashed = hash_password(password, rounds=12)
    print(f"Plaintext password : {password}")
    print(f"bcrypt hash (store this, never the plaintext): {hashed.decode()}")

    # 2. Verify with the correct password
    correct_check = verify_password(password, hashed)
    print(f"\nVerification with CORRECT password: {correct_check}")
    assert correct_check

    # 3. Verify with an incorrect password
    wrong_check = verify_password("wrongPassword123", hashed)
    print(f"Verification with WRONG password:   {wrong_check}")
    assert not wrong_check

    # 4. Demonstrate that hashing the same password twice yields
    #    DIFFERENT hashes (because of the random salt) - this is
    #    expected and correct behaviour, and is what defeats
    #    rainbow-table / precomputation attacks.
    hashed_again = hash_password(password, rounds=12)
    print(f"\nSame password hashed twice produces different hashes:")
    print(f"  Hash 1: {hashed.decode()}")
    print(f"  Hash 2: {hashed_again.decode()}")
    print(f"  Hashes are different: {hashed != hashed_again}")
    print(f"  Both still verify correctly: "
          f"{verify_password(password, hashed) and verify_password(password, hashed_again)}")


if __name__ == "__main__":
    demo()
