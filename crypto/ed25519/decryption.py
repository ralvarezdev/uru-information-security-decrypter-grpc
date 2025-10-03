def decrypt_file(
	encrypted_file_bytes: bytes,
	private_key,
) -> bytes:
	"""
	Decrypt a file using the provided private key.

	Args:
		encrypted_file_bytes: The encrypted file content to decrypt.
		private_key: Private key to use for decryption.

	Returns:
		bytes: The encrypted file content.
	"""
	# Decrypt the file using ED25519 private key
	decrypted = private_key.decrypt(
		encrypted_file_bytes,
	)
	return decrypted