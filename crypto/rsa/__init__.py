import os

from dotenv import load_dotenv
from crypto import (
	load_private_key_from_file,
	load_public_key_from_file,
	BASE_DIR,
)

# Load environment variables from a .env file
load_dotenv()

# Load tender's private key from PEM file
TENDER_PRIVATE_KEY_FILENAME = "tender_private_key.pem"
TENDER_PRIVATE_KEY = load_private_key_from_file(os.path.join(BASE_DIR, TENDER_PRIVATE_KEY_FILENAME))

# Load tender's public key from PEM file
TENDER_PUBLIC_KEY_FILENAME = "tender_public_key.pem"
TENDER_PUBLIC_KEY = load_public_key_from_file(os.path.join(BASE_DIR, TENDER_PUBLIC_KEY_FILENAME))