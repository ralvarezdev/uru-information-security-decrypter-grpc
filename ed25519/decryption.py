from typing import LiteralString

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def decrypt_file(
	file_path: LiteralString | str | bytes,
	private_key,
) -> bytes:
	"""
	Decrypt a file using the provided private key.

	Args:
		file_path: Path to the file to be decrypted.
		private_key: Private key to use for decryption.

	Returns:
		bytes: The encrypted file content.
	"""
	# Read the file content
	with open(file_path, 'rb') as f:
		file_bytes = f.read()

	# Decrypt the file using ED25519 private key
	decrypted = private_key.decrypt(
		file_bytes,
	)
	return decrypted