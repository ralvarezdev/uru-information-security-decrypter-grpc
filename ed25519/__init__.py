import os

from dotenv import load_dotenv
from ed25519.keys import load_private_key_from_file, load_public_key_from_file

# Load environment variables from a .env file
load_dotenv()

# Load issuer's private key from PEM file
issuer_private_key = load_private_key_from_file(os.getenv("PRIVATE_KEY_PATH"))

# Load issuer's public key from PEM file
issuer_public_key = load_public_key_from_file(os.getenv("PUBLIC_KEY_PATH"))

# Data path
data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "data")