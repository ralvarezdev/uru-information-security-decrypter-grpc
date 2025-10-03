from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_file_with_symmetric_key(encrypted_bytes: bytes, key: bytes) -> bytes:
    """
    Decrypt file bytes using a symmetric key (Fernet/AES).

    Args:
        encrypted_bytes (bytes): The encrypted file content.
        key (bytes): The symmetric key (32 bytes for Fernet).

    Returns:
        bytes: The decrypted file content.
    """
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_bytes)
    return decrypted

def decrypt_symmetric_key_with_private_key(encrypted_key: bytes, private_key) -> bytes:
	"""
	Decrypt a symmetric key using a private key.

	Args:
		encrypted_key (bytes): The encrypted symmetric key.
		private_key: The private key object for decryption.

	Returns:
		bytes: The decrypted symmetric key.
	"""
	symmetric_key = private_key.decrypt(
		encrypted_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
			)
		)
	return symmetric_key