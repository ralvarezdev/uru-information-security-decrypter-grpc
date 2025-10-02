from microservice import grpc

import ralvarezdev.certificate_pb2_grpc as certificate_pb2_grpc

def create_grpc_client(host: str, port: int):
    """
    Creates and returns a gRPC client stub.

	Args:
		host (str): The server host.
		port (int): The server port.

	Returns:
		certificate_pb2_grpc.CertificateStub: The gRPC client stub.
    """
    channel = grpc.insecure_channel(f"{host}:{port}")
    stub = certificate_pb2_grpc.CertificateStub(channel)
    return stub