from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import secrets
import os
import base64

# --- Password Hashing Functions ---
def hash_password(password):
    """
    Hash a password using SHA-256 with a random salt.
    
    Args:
        password (str): The plain text password to hash
    
    Returns:
        str: The salted hash in format "salt:hash"
    """
    # Generate a random salt (32 bytes = 256 bits)
    salt = secrets.token_hex(32)
    
    # Combine password and salt, then hash with SHA-256
    password_salt = password + salt
    hash_object = hashlib.sha256(password_salt.encode('utf-8'))
    password_hash = hash_object.hexdigest()
    
    # Return salt and hash combined (salt:hash format)
    return f"{salt}:{password_hash}"

def verify_password(password, stored_hash):
    """
    Verify a password against a stored hash.
    
    Args:
        password (str): The plain text password to verify
        stored_hash (str): The stored hash in format "salt:hash"
    
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        # Split salt and hash
        salt, hash_to_verify = stored_hash.split(':', 1)
        
        # Hash the provided password with the stored salt
        password_salt = password + salt
        hash_object = hashlib.sha256(password_salt.encode('utf-8'))
        password_hash = hash_object.hexdigest()
        
        # Compare hashes using secrets.compare_digest to prevent timing attacks
        return secrets.compare_digest(password_hash, hash_to_verify)
    
    except ValueError:
        # Handle case where stored_hash doesn't contain ':'
        return False

# --- AES Encryption Function ---
def encrypt_password(password: str, secret_key: bytes):
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Derive a 256-bit key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(secret_key)

    # Pad the password
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_password) + encryptor.finalize()

    # Return base64-encoded values
    return base64.b64encode(salt + iv + ciphertext).decode('utf-8')

def decrypt_password(encrypted_data: str, secret_key: bytes) -> str:
    # Decode the base64-encoded string
    encrypted_data_bytes = base64.b64decode(encrypted_data)

    # Extract salt, IV, and ciphertext
    salt = encrypted_data_bytes[:16]
    iv = encrypted_data_bytes[16:32]
    ciphertext = encrypted_data_bytes[32:]

    # Derive the key using the same method as encryption
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(secret_key)

    # Decrypt the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode('utf-8')
