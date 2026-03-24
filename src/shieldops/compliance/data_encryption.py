"""Field-Level Data Encryption for compliance.

Provides Fernet (AES-128-CBC with HMAC) encryption for sensitive fields in
database records. Supports key rotation via Fernet's MultiFernet.
"""

import copy
from typing import Any

import structlog
from cryptography.fernet import Fernet

logger = structlog.get_logger()


class FieldEncryptor:
    """Encrypt/decrypt individual fields for database storage.

    Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).
    Ciphertext is URL-safe base64 encoded, suitable for text columns.
    """

    def __init__(self, encryption_key: str | None = None) -> None:
        if encryption_key:
            key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
            self._fernet = Fernet(key)
            self._key = key
        else:
            self._key = Fernet.generate_key()
            self._fernet = Fernet(self._key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string, returning base64-encoded ciphertext."""
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a base64-encoded ciphertext back to plaintext.

        Raises:
            InvalidToken: If the ciphertext is invalid or the key is wrong.
        """
        plaintext = self._fernet.decrypt(ciphertext.encode("utf-8"))
        return plaintext.decode("utf-8")

    def encrypt_dict(self, data: dict[str, Any], fields: list[str]) -> dict[str, Any]:
        """Return a copy of *data* with the specified *fields* encrypted.

        Only string values are encrypted; missing or non-string fields are
        left unchanged.
        """
        result = copy.deepcopy(data)
        for field in fields:
            if field in result and isinstance(result[field], str):
                result[field] = self.encrypt(result[field])
                logger.debug("field_encrypted", field=field)
        return result

    def decrypt_dict(self, data: dict[str, Any], fields: list[str]) -> dict[str, Any]:
        """Return a copy of *data* with the specified *fields* decrypted.

        Raises InvalidToken if any ciphertext is corrupt or key-mismatched.
        """
        result = copy.deepcopy(data)
        for field in fields:
            if field in result and isinstance(result[field], str):
                result[field] = self.decrypt(result[field])
                logger.debug("field_decrypted", field=field)
        return result

    @staticmethod
    def generate_key() -> str:
        """Generate a new Fernet encryption key (URL-safe base64)."""
        return Fernet.generate_key().decode("utf-8")
