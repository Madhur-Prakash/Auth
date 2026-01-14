from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

class Hash:
    # Argon2 configuration (safe defaults)
    _ph = PasswordHasher(
        time_cost=3,        # iterations
        memory_cost=65536,  # 64 MB
        parallelism=2,
        hash_len=32,
        salt_len=16
    )

    @staticmethod
    def generate_hash(password: str) -> str:
        """
        Hash a password using Argon2.
        Use ONLY for user passwords.
        """
        try:
            if not password or not password.strip():
                raise ValueError("Password cannot be empty")

            return Hash._ph.hash(password)

        except Exception:
            raise ValueError("Password hashing failed")

    @staticmethod
    async def verify(hashed_password: str, plain_password: str) -> bool:
        """
        Verify a password against an Argon2 hash.
        """
        try:
            if not hashed_password or not plain_password:
                return False

            Hash._ph.verify(hashed_password, plain_password)
            return True

        except VerifyMismatchError:
            return False
        except VerificationError:
            return False
        except Exception:
            return False
