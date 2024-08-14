import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from hashlib import sha256
import json

def generate_key():
    return b64encode(os.urandom(16)).decode('utf-8')

def encrypt_data(data, key):
    key_bytes = b64decode(key)  # Decode the base64 key to bytes
    cipher = AES.new(key_bytes, AES.MODE_GCM)  # Create a new AES cipher object in GCM mode
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode('utf-8'))  # Encrypt the data and get the tag
    # Combine nonce, tag, and ciphertext, then encode in base64
    return b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_data(encrypted_data, key):
    key_bytes = b64decode(key)  # Decode the base64 key to bytes
    data = b64decode(encrypted_data)  # Decode the base64 encrypted data to bytes
    nonce = data[:16]  # Extract the nonce from the data
    tag = data[16:32]  # Extract the tag from the data
    ciphertext = data[32:]  # Extract the ciphertext from the data
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)  # Create a new AES cipher object with the nonce
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt the ciphertext and verify the tag
    return json.loads(decrypted_data.decode('utf-8'))  # Decode the decrypted data from JSON

def get_hashed_data(data):
    return sha256(data.encode('utf-8')).hexdigest()

def check_hash(data, hash):
    return get_hashed_data(data) == hash