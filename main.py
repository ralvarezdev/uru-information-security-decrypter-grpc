from argparse import ArgumentParser
import os
from concurrent import futures
from microservice import grpc

from cryptography import x509

import ralvarezdev.decrypter_pb2 as decrypter_pb2
import ralvarezdev.decrypter_pb2_grpc as decrypter_pb2_grpc

from ed25519 import data_path
from ed25519.decryption import decrypt_file


class DecrypterServicer(decrypter_pb2_grpc.DecrypterServicer):
	def SendEncryptedFile(self, request_iterator, context):
		# Get the certificate bytes from metadata
		cert_bytes = None
		for key, value in context.invocation_metadata():
			if key == 'certificate':
				cert_bytes = value.encode('utf-8')
				break
		if not cert_bytes:
			context.set_code(grpc.StatusCode.UNAUTHENTICATED)
			context.set_details('Certificate metadata is required')
			print("Missing certificate metadata")
			return encrypter_pb2.Empty()

	def ListFiles(self, request, context):
		# List all encrypted files in data_path
		files = [f for f in os.listdir(data_path) if f.endswith('.enc')]
		return decrypter_pb2.ListFilesResponse(filenames=files)

	def DecryptFile(self, request, context):
		# Validate request
		filename = request.filename
		if not filename or not filename.endswith('.enc'):
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Invalid filename')
			return

		# Get the encrypted file and certificate paths
		enc_path = os.path.join(data_path, filename)
		cert_path = enc_path.rsplit('.enc', 1)[0] + '.crt'
		if not os.path.exists(enc_path) or not os.path.exists(cert_path):
			context.set_code(grpc.StatusCode.NOT_FOUND)
			context.set_details('File or certificate not found')
			return

		# Stream file content in chunks
		chunk_size = 4096
		with open(enc_path, 'rb') as f_enc, open(cert_path, 'rb') as f_cert:
			encrypted_cert_content = f_cert.read()
			while True:
				encrypted_file_content = f_enc.read(chunk_size)
				if not encrypted_file_content:
					break

		# Decrypt the certificate and file content
		cert_content = decrypt_file(cert_path, request.private_key)
		file_content = decrypt_file(enc_path, request.private_key)

		# Converted the certificate decrypted content to certificate object
		cert = x509.load_pem_x509_certificate(cert_content)

		# Extract the subject details from the certificate
		subject = cert.subject
		common_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
		organization = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
		organizational_unit = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
		locality = subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[0].value
		state = subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)[0].value
		country = subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value
		print(f'Decrypted file "{filename}" for {common_name}, {organization}, {organizational_unit}, {locality}, {state}, {country}')

		yield decrypter_pb2.DecryptFileResponse(
			file_content=file_content,
			common_name=common_name,
			organization=organization,
			organizational_unit=organizational_unit,
			locality=locality,
			state=state,
			country=country,
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
