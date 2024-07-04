from flask import Flask, request, jsonify
from pymongo import MongoClient
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import os
import base64
import json

app = Flask(__name__)

# Load environment variables
MONGODB_URI = os.getenv('MONGODB_URI')
PUBLIC_KEY_PATH = os.getenv('PUBLIC_KEY_PATH')
PRIVATE_KEY_PATH = os.getenv('PRIVATE_KEY_PATH')

# MongoDB setup
db = Key(MONGODB_URI)
collection = client.get_database()

# Routes
@app.route('/weather', methods=['POST'])
def receive_weather_data():
    data = request.get_json()

    # Extract data, signature, and public key
    weather_data = data['weather_data']
    signature = data['signature']
    public_key = data['public_key']

    # Verify integrity of data using hashes (optional)
    if verify_data_integrity(weather_data, signature):
        # Verify the signature
        if verify_signature(public_key, signature, weather_data):
            # Store data in MongoDB
            collection = db.weather_data
            collection.insert_one({
                'weather_data': weather_data,
                'signature': signature,
                'public_key': public_key
            })
            return jsonify({'message': 'Weather data received and verified successfully.'}), 200
        else:
            return jsonify({'error': 'Signature verification failed.'}), 400
    else:
        return jsonify({'error': 'Data integrity check failed.'}), 400

def verify_data_integrity(data, signature):
    # Implement data integrity verification (e.g., hash comparison)
    # For simplicity, you can use hash functions from cryptography library
    return True  # Placeholder; implement according to your needs

def verify_signature(public_key, signature, data):
    # Load public key
    key = load_pem_public_key(public_key.encode(), backend=default_backend())

    # Verify signature
    try:
        key.verify(
            base64.b64decode(signature),
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {str(e)}")
        return False

if __name__ == '__main__':
    app.run(debug=True)
