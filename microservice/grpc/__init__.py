import os

from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Get gRPC server configuration from environment variables
CERTIFICATE_GRPC_HOST = os.getenv("CERTIFICATE_GRPC_HOST")
CERTIFICATE_GRPC_PORT = int(os.getenv("CERTIFICATE_GRPC_PORT"))
