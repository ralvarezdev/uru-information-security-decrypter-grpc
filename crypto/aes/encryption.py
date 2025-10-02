def decrypt_symmetric_key_with_private_key(encrypted_key: bytes, private_key) -> bytes:
	"""
	Decrypt a symmetric key using a private key.

	Args:
		encrypted_key (bytes): The encrypted symmetric key.
		private_key: The private key object for decryption.

	Returns:
		bytes: The decrypted symmetric key.
	"""
	decrypted_key = private_key.decrypt(
		encrypted_key,
	)
	return decrypted_key