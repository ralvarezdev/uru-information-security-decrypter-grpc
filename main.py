from argparse import ArgumentParser
import os
from concurrent import futures

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import ralvarezdev.decrypter_pb2 as decrypter_pb2
import ralvarezdev.decrypter_pb2_grpc as decrypter_pb2_grpc
from database.psycopg.connection import (
	remove_encrypted_file,
	remove_encrypted_files,
	add_encrypted_file,
	list_active_files,
)
from microservice.grpc import (
	CERTIFICATE_GRPC_HOST,
	CERTIFICATE_GRPC_PORT,
)
from microservice.grpc.certificate import create_grpc_client
from crypto.ed25519 import (
	TENDER_PRIVATE_KEY,
	DATA_PATH,
)
from crypto.ed25519.decryption import decrypt_file
from crypto.aes.encryption import decrypt_symmetric_key_with_private_key
from crypto.sha.signature import verify_signature


class DecrypterServicer(decrypter_pb2_grpc.DecrypterServicer):
	def ReceiveEncryptedFile(self, request_iterator, context):
		# Get the certificate bytes and AES-256 key from metadata
		cert_bytes = None
		encrypted_aes_256_key = None
		for key, value in context.invocation_metadata():
			if key == 'certificate':
				cert_bytes = value.decode('utf-8')
				break
			elif key == 'encrypted_aes_256_key':
				encrypted_aes_256_key = bytes.fromhex(value)
				break
		if not cert_bytes:
			context.set_code(grpc.StatusCode.UNAUTHENTICATED)
			context.set_details('Certificate metadata is required')
			print("Missing certificate metadata")
			return decrypter_pb2.Empty()
		if not encrypted_aes_256_key:
			context.set_code(grpc.StatusCode.UNAUTHENTICATED)
			context.set_details('Encrypted AES-256 key metadata is required')
			print("Missing encrypted AES-256 key metadata")
			return decrypter_pb2.Empty()

		# Create the gRPC client to validate the certificate
		cert_client = create_grpc_client(
			host=CERTIFICATE_GRPC_HOST,
			port=CERTIFICATE_GRPC_PORT,
		)
		try:
			cert_client.ValidateCertificate(
				certificate_content=cert_bytes,
			)
		except grpc.RpcError as e:
			context.set_code(e.code())
			context.set_details(f'Certificate validation failed: {e.details()}')
			print(f'Certificate validation failed: {e.details()}')
			return decrypter_pb2.Empty()

		# Accumulate file chunks
		encrypted_file_bytes = bytearray()
		signature = None
		filename = None

		# Process each chunk in the stream
		for request in request_iterator:
			# Validate request
			if not request.filename or not request.encrypted_content:
				context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
				context.set_details('Filename and encrypted_content are required')
				print("Invalid request: missing filename or encrypted_content")
				return decrypter_pb2.Empty()

			# Ensure all chunks belong to the same file
			if not filename:
				filename = request.filename
			elif filename != request.filename:
				context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
				context.set_details('All chunks must have the same filename')
				print("All chunks must have the same filename")
				return decrypter_pb2.Empty

			# Ensure signature is consistent across chunks
			if not signature:
				signature = request.content_signature
			elif signature != request.content_signature:
				context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
				context.set_details('All chunks must have the same content_signature')
				print("All chunks must have the same content_signature")
				return decrypter_pb2.Empty

			# Append chunk to the file bytes
			encrypted_file_bytes.extend(request.encrypted_content)

		# Load the certificate
		cert = x509.load_pem_x509_certificate(cert_bytes)

		# Get the details from the certificate
		subject = cert.subject
		common_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
		print(f'Received file "{filename}" from {common_name}')

		# Ensure company directory exists
		company_dir = os.path.join(DATA_PATH, common_name)
		os.makedirs(company_dir, exist_ok=True)

		# Store in the database the encrypted file metadata
		add_encrypted_file(
			common_name=common_name,
			filename=filename,
		)

		# Save the encrypted file, removing any existing file with the same name
		enc_path = os.path.join(company_dir, filename)
		if os.path.exists(enc_path):
			os.remove(enc_path)
			print(f'Removed existing file: {enc_path}')

		# Write the encrypted file to disk
		with open(enc_path, 'wb') as f_enc:
			f_enc.write(encrypted_file_bytes)

		# Save the signature to a .sig file
		sig_path = os.path.join(company_dir, filename + '.sig')
		with open(sig_path, 'wb') as f_sig:
			f_sig.write(signature)
			print(f'Saved signature file: {sig_path}')

		# Save the encrypted AES-256 key to a .key file
		key_path = os.path.join(company_dir, filename + '.key')
		with open(key_path, 'wb') as f_key:
			f_key.write(encrypted_aes_256_key)
			print(f'Saved encrypted AES-256 key file: {key_path}')

		return decrypter_pb2.Empty()

	def ListActiveFiles(self, request, context):
		# List active files from the database
		active_files = list_active_files()

		# Organize files by company
		company_files_dict = {}
		for file in active_files:
			common_name = file['common_name']
			filename = file['filename']
			if common_name not in company_files_dict:
				company_files_dict[common_name] = []
			company_files_dict[common_name].append(filename)

		# Prepare the response
		company_files_list = []
		for common_name, filenames in company_files_dict.items():
			company_files_list.append(
				decrypter_pb2.CompanyFiles(
					common_name=common_name,
					filenames=filenames,
				)
			)

		return decrypter_pb2.ListActiveFilesResponse(company_files=company_files_list)

	def RemoveEncryptedFile(self, request, context):
		# Validate request
		if not request.filename or not request.common_name:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Filename and common_name are required')
			return decrypter_pb2.Empty()

		# Remove the file metadata from the database
		remove_encrypted_file(
			filename=request.filename,
			common_name=request.common_name,
		)

		# Remove the encrypted file from the filesystem
		file_path = os.path.join(DATA_PATH, request.common_name, request.filename)
		if os.path.exists(file_path):
			os.remove(file_path)
			print(f'Removed file: {file_path}')
		else:
			print(f'File not found for removal: {file_path}')

		return decrypter_pb2.Empty()

	def RemoveEncryptedFiles(self, request, context):
		# Remove all file metadata from the database
		remove_encrypted_files()

		# Remove all encrypted files from the filesystem
		if os.path.exists(DATA_PATH):
			for root, dirs, files in os.walk(DATA_PATH):
				for file in files:
					file_path = os.path.join(root, file)
					os.remove(file_path)
					print(f'Removed file: {file_path}')
		else:
			print(f'Data path not found for removal: {DATA_PATH}')

		return decrypter_pb2.Empty()

	def DecryptFile(self, request, context):
		# Validate request
		filename = request.filename
		common_name = request.common_name
		if not filename:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Invalid filename')
			return decrypter_pb2.DecryptFileResponse()
		if not common_name:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Invalid common_name')
			return decrypter_pb2.DecryptFileResponse()

		# Request the public key from the certificate microservice
		cert_client = create_grpc_client(
			host=CERTIFICATE_GRPC_HOST,
			port=CERTIFICATE_GRPC_PORT,
		)
		try:
			cert_response = cert_client.GetPublicKeyByCommonName(
				common_name=common_name,
			)
			public_key_bytes = cert_response.public_key
		except grpc.RpcError as e:
			context.set_code(e.code())
			context.set_details(f'Failed to get public key: {e.details()}')
			print(f'Failed to get public key: {e.details()}')
			return decrypter_pb2.DecryptFileResponse()

		# Load the public key
		public_key = serialization.load_pem_public_key(public_key_bytes)

		# Get the encrypted AES-256 key
		company_dir = os.path.join(DATA_PATH, common_name)
		enc_key_path = os.path.join(company_dir, filename + '.key')
		if not os.path.exists(enc_key_path):
			context.set_code(grpc.StatusCode.NOT_FOUND)
			context.set_details('Encrypted AES-256 key file not found')
			print('Encrypted AES-256 key file not found')
			return decrypter_pb2.DecryptFileResponse()
		with open(enc_key_path, 'rb') as f_key:
			encrypted_aes_256_key = f_key.read()

		# Decrypt the AES-256 key with the server's private key
		decrypted_key = decrypt_symmetric_key_with_private_key(
			encrypted_key=encrypted_aes_256_key,
			private_key=TENDER_PRIVATE_KEY,
		)

		# Get the encrypted file
		enc_path = os.path.join(company_dir, filename)
		if not os.path.exists(enc_path):
			context.set_code(grpc.StatusCode.NOT_FOUND)
			context.set_details('Encrypted file not found')
			print('Encrypted file not found')
			return decrypter_pb2.DecryptFileResponse()
		with open(enc_path, 'rb') as f_enc:
			encrypted_file_bytes = f_enc.read()

		# Decrypt the file content with the decrypted AES-256 key
		file_bytes = decrypt_file(encrypted_file_bytes, decrypted_key)

		# Load the signature
		sig_path = os.path.join(company_dir, filename + '.sig')
		if not os.path.exists(sig_path):
			context.set_code(grpc.StatusCode.NOT_FOUND)
			context.set_details('Signature file not found')
			print('Signature file not found')
			return decrypter_pb2.DecryptFileResponse()
		with open(sig_path, 'rb') as f_sig:
			signature = f_sig.read()

		# Verify the file signature with the certificate's public key
		if not verify_signature(file_bytes, signature, public_key):
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Invalid file signature')
			print('Invalid file signature')
			return decrypter_pb2.Empty()

		# Return the decrypted file content by chunks
		chunk_size = 1024 * 1024  # 1 MB
		for i in range(0, len(file_bytes), chunk_size):
			yield decrypter_pb2.DecryptFileResponse(
				file_content=file_bytes[i:i + chunk_size],
			)


def serve(host: str, port: int):
	"""
	Start the gRPC server.

	Args:
		host (str): Host to listen on.
		port (int): Port to listen on.
	"""
	# Create gRPC server
	server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

	# Register the servicer
	decrypter_pb2_grpc.add_DecrypterServicer_to_server(
		DecrypterServicer(),
		server,
		)
	server.add_insecure_port(host + ':' + str(port))
	server.start()
	server.wait_for_termination()


if __name__ == '__main__':
	# Get port from arguments
	parser = ArgumentParser()
	parser.add_argument(
		'--host',
		type=str,
		default='localhost',
		help='Host to listen on',
		)
	parser.add_argument('--port', type=int, help='Port to listen on')
	args = parser.parse_args()
	print(f'Starting server on {args.host}:{args.port}')

	# Start the gRPC server
	serve(args.host, args.port)
