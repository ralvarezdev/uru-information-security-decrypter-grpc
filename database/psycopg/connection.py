import psycopg
import logging

from database.psycopg import (
	POSTGRES_DB,
	POSTGRES_USER,
	POSTGRES_PASSWORD,
	POSTGRES_HOST,
	POSTGRES_PORT
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_connection():
	"""Create a connection to the PostgreSQL database."""
	try:
		conn = psycopg.connect(
			dbname=POSTGRES_DB,
			user=POSTGRES_USER,
			password=POSTGRES_PASSWORD,
			host=POSTGRES_HOST,
			port=POSTGRES_PORT
		)
		logger.info("Connection to the database was successful.")
		return conn
	except Exception as e:
		logger.error(f"An error occurred while connecting to the database: {e}")
		return None

def remove_encrypted_file(filename: str, common_name: str):
	"""
	Mark an encrypted file as removed in the database.

	Args:
		filename (str): The name of the file to remove.
		common_name (str): The common name associated with the file.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"CALL remove_encrypted_file(%s, %s);",
					(filename, common_name),
				)
				conn.commit()
				logger.info(f"File {filename} marked as removed.")
			except Exception as e:
				logger.error(f"An error occurred while removing the file: {e}")

def remove_encrypted_files():
	"""
	Mark all encrypted files as removed in the database.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"CALL remove_encrypted_files();",
				)
				conn.commit()
				logger.info("All files marked as removed.")
			except Exception as e:
				logger.error(f"An error occurred while removing the files: {e}")

def add_encrypted_file(filename: str, common_name: str):
	"""
	Add a new encrypted file to the database.

	Args:
		filename (str): The name of the file to add.
		common_name (str): The common name associated with the file.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"CALL add_encrypted_file(%s, %s);",
					(filename, common_name),
				)
				conn.commit()
				logger.info(f"File {filename} added successfully.")
			except Exception as e:
				logger.error(f"An error occurred while adding the file: {e}")

def list_active_files():
	"""
	List all active (not removed) encrypted files from the database.

	Returns:
		list of tuples: A list of tuples containing file names and their upload timestamps.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute('SELECT * FROM list_active_files()')
				files = cur.fetchall()
				logger.info(f"Retrieved {len(files)} active files.")
				return files
			except Exception as e:
				logger.error(f"An error occurred while listing the files: {e}")
				return []