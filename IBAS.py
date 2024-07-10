from flask import Flask, request, jsonify
from pymongo import MongoClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import base64

app = Flask(__name__)

# Load environment variables
from dotenv import load_dotenv
load_dotenv('IBAS.env')

# Connect to MongoDB
client = MongoClient(os.getenv('MONGO_URI'))
db = client[os.getenv('MONGO_DB_NAME')]
keys_collection = db['keys']
data_collection = db['data']

# Key management functions
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key, private=False):
    if private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    source = request.json.get('source')
    private_key, public_key = generate_key_pair()
    
    keys_collection.insert_one({
        'source': source,
        'private_key': base64.b64encode(serialize_key(private_key, private=True)).decode('utf-8'),
        'public_key': base64.b64encode(serialize_key(public_key)).decode('utf-8')
    })
    
    return jsonify({'message': 'Keys generated and stored successfully'}), 201

@app.route('/fetch_weather_data', methods=['POST'])
def fetch_weather_data():
    # This is a placeholder for actual data fetching logic from weather providers
    source = request.json.get('source')
    weather_data = request.json.get('data')
    private_key_data = keys_collection.find_one({'source': source})['private_key']
    private_key = serialization.load_pem_private_key(base64.b64decode(private_key_data.encode('utf-8')), password=None)
    
    # Sign the data
    signature = private_key.sign(
        weather_data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Store data and signature
    data_collection.insert_one({
        'source': source,
        'data': weather_data,
        'signature': base64.b64encode(signature).decode('utf-8'),
        'public_key': keys_collection.find_one({'source': source})['public_key']
    })
    
    return jsonify({'message': 'Weather data fetched, signed, and stored successfully'}), 201

@app.route('/verify_data', methods=['GET'])
def verify_data():
    source = request.args.get('source')
    record = data_collection.find_one({'source': source})
    if not record:
        return jsonify({'error': 'Data not found'}), 404
    
    public_key_data = record['public_key']
    public_key = serialization.load_pem_public_key(base64.b64decode(public_key_data.encode('utf-8')))
    
    try:
        public_key.verify(
            base64.b64decode(record['signature'].encode('utf-8')),
            record['data'].encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({'message': 'Data is valid'}), 200
    except Exception as e:
        return jsonify({'error': 'Data verification failed', 'details': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
