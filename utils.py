import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from hashlib import sha256
import json

def generate_key():
    return b64encode(os.urandom(16)).decode('utf-8')

def encrypt_data(data, key):
    key_bytes = b64decode(key)
    cipher = AES.new(key_bytes, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode('utf-8'))
    return b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_data(encrypted_data, key):
    key_bytes = b64decode(key)
    data = b64decode(encrypted_data)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(decrypted_data.decode('utf-8'))

def get_hashed_data(data):
    return sha256(data.encode('utf-8')).hexdigest()

def check_hash(data, hash):
    return get_hashed_data(data) == hash
