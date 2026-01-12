import base64
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionHelper:
    """
    Helper class for encrypting and decrypting sensitive user data
    using AES-256-GCM.
    """

    def __init__(self, base64_key: str):
        self.key = base64.b64decode(base64_key)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts plaintext and returns a base64-encoded string.
        """
        nonce = os.urandom(12)  # 96-bit nonce (recommended for GCM)
        ciphertext = self.aesgcm.encrypt(
            nonce,
            plaintext.encode(),
            None
        )
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypts base64-encoded encrypted data.
        """
        data = base64.b64decode(encrypted_text)
        nonce = data[:12]
        ciphertext = data[12:]

        plaintext = self.aesgcm.decrypt(
            nonce,
            ciphertext,
            None
        )
        return plaintext.decode()

    @staticmethod # method to generate a new key
    def generate_base64_key() -> str:
        """
        Generates a new base64-encoded 32-byte key for AES-256-GCM.
        """ 
        key = AESGCM.generate_key(bit_length=256)
        return base64.b64encode(key).decode()
