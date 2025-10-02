def decrypt_file(
	file_bytes: bytes,
	private_key,
) -> bytes:
	"""
	Decrypt a file using the provided private key.

	Args:
		file_bytes: The file content to decrypt.
		private_key: Private key to use for decryption.

	Returns:
		bytes: The encrypted file content.
	"""
	# Decrypt the file using ED25519 private key
	decrypted = private_key.decrypt(
		file_bytes,
	)
	return decrypted