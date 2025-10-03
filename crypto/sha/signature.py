import hashlib


def verify_signature(file_bytes: bytes, signature: bytes, public_key) -> bool:
	"""
	Verify the signature of a file using the provided public key.

	Args:
		file_bytes: The original file bytes.
		signature: The signature to verify.
		public_key: The public key object for verification.

	Returns:
		bool: True if the signature is valid, False otherwise.
	"""
	# Hash the file contents
	file_hash = hashlib.sha256(file_bytes).digest()

	try:
		# Verify the signature
		public_key.verify(signature, file_hash)
		return True
	except Exception:
		return False