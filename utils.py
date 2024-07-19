import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from hashlib import sha256
import json

def generate_key():
    """
    Generates a random 128-bit key and returns it encoded in base64.
    This key will be used for AES encryption and decryption.
    
    Returns:
        str: A base64 encoded string of the generated key.
    """
    return b64encode(os.urandom(16)).decode('utf-8')

def encrypt_data(data, key):
    """
    Encrypts data using AES (GCM mode) with the provided key.
    
    Args:
        data (dict): The data to be encrypted (must be JSON serializable).
        key (str): The base64 encoded AES key for encryption.
    
    Returns:
        str: The encrypted data, encoded in base64.
    """
    key_bytes = b64decode(key)  # Decode the base64 key to bytes
    cipher = AES.new(key_bytes, AES.MODE_GCM)  # Create a new AES cipher object in GCM mode
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode('utf-8'))  # Encrypt the data and get the tag
    # Combine nonce, tag, and ciphertext, then encode in base64
    return b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_data(encrypted_data, key):
    """
    Decrypts data encrypted with AES (GCM mode) using the provided key.
    
    Args:
        encrypted_data (str): The base64 encoded encrypted data.
        key (str): The base64 encoded AES key used for decryption.
    
    Returns:
        dict: The decrypted data.
    """
    key_bytes = b64decode(key)  # Decode the base64 key to bytes
    data = b64decode(encrypted_data)  # Decode the base64 encrypted data to bytes
    nonce = data[:16]  # Extract the nonce from the data
    tag = data[16:32]  # Extract the tag from the data
    ciphertext = data[32:]  # Extract the ciphertext from the data
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)  # Create a new AES cipher object with the nonce
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt the ciphertext and verify the tag
    return json.loads(decrypted_data.decode('utf-8'))  # Decode the decrypted data from JSON

def get_hashed_data(data):
    """
    Computes the SHA-256 hash of the given data.
    
    Args:
        data (str): The data to be hashed.
    
    Returns:
        str: The hexadecimal representation of the hash.
    """
    return sha256(data.encode('utf-8')).hexdigest()

def check_hash(data, hash):
    """
    Checks if the hash of the given data matches the provided hash.
    
    Args:
        data (str): The data to be hashed and compared.
        hash (str): The hash to compare against.
    
    Returns:
        bool: True if the hash matches, False otherwise.
    """
    return get_hashed_data(data) == hash
