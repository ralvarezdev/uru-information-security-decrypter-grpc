from argparse import ArgumentParser
import os
from concurrent import futures
import grpc

import ralvarezdev.decrypter_pb2 as decrypter_pb2
import ralvarezdev.decrypter_pb2_grpc as decrypter_pb2_grpc

from ed25519 import data_path
from ed25519.decryption import decrypt_file

class DecrypterServicer(decrypter_pb2_grpc.DecrypterServicer):
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

		yield decrypter_pb2.DecryptFileResponse(
			file_content=file_content,
			certificate_content=cert_content,
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
