import os
import requests
from pymongo import MongoClient
from dotenv import load_dotenv
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import json
import logging
from flask import Flask, request, jsonify
import sys

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load environment variables
load_dotenv()

# Read environment variables
MONGO_URI = os.environ.get("AZURE_COSMOS_CONNECTIONSTRING")
if not MONGO_URI:
    logger.error("MongoDB URI not found in environment variables.")
    sys.exit(1)

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.get_database('ibas-server')
collection = db.weather_records
keys_collection = db.transitKeys

# Function to test MongoDB connection
@app.before_first_request
def test_db_connection():
    try:
        client.admin.command('ping')
        logger.info("MongoDB connection established successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        sys.exit(1)

class SimpleSigner:
    def __init__(self, identity):
        self.identity = identity
        self.key = None
        self.public_key = None

    def generate_keys(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def save_keys(self, private_key_file, public_key_file):
        with open(private_key_file, 'wb') as f:
            f.write(self.key.export_key())
        with open(public_key_file, 'wb') as f:
            f.write(self.public_key.export_key())

    def load_keys(self, private_key_file, public_key_file):
        with open(private_key_file, 'rb') as f:
            self.key = RSA.import_key(f.read())
        with open(public_key_file, 'rb') as f:
            self.public_key = RSA.import_key(f.read())

    def sign(self, data):
        message = self.identity.encode() + data
        h = SHA256.new(message)
        signature = pkcs1_15.new(self.key).sign(h)
        return signature

    def verify(self, identity, data, signature):
        message = identity.encode() + data
        h = SHA256.new(message)
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def aggregate_signatures(signatures):
        return b''.join(signatures)

    @staticmethod
    def verify_aggregate(identities, data, aggregate_signature, public_keys):
        signature_len = len(aggregate_signature) // len(public_keys)
        for i, pub_key in enumerate(public_keys):
            message = identities[i].encode() + data
            message_hash = SHA256.new(message)
            signature_part = aggregate_signature[i * signature_len:(i + 1) * signature_len]
            try:
                pkcs1_15.new(pub_key).verify(message_hash, signature_part)
            except (ValueError, TypeError):
                return False
        return True

@app.route('/', methods=['GET'])
def home():
    return "IBAS API is running"

@app.route('/setup-identity', methods=['POST'])
def setup_identity():
    identity = request.json.get('identity')
    if not identity:
        return jsonify({"error": "Identity is required"}), 400

    signer = SimpleSigner(identity)
    signer.generate_keys()
    signer.save_keys_to_db()
    return jsonify({"message": f"Keys for identity '{identity}' have been generated and stored in the database."}), 200

def fetch_data():
    # Simulate fetching data from an external source
    data = {
        'temperature': 25.3,
        'humidity': 70,
        'city': 'Sample City'
    }
    return json.dumps(data).encode()

@app.route('/verify-signatures', methods=['POST'])
def verify_signatures():
    signers = []
    public_keys = []
    signatures = []

    num_signers = request.json.get('num_signers')
    identities = request.json.get('identities')
    
    if not num_signers or not identities or len(identities) != num_signers:
        return jsonify({"error": "Invalid number of signers or identities"}), 400

    for identity in identities:
        signer = SimpleSigner(identity)
        try:
            signer.load_keys_from_db()
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        signers.append(signer)
        public_keys.append(signer.public_key)

    data = fetch_data()

        for signer in signers:
            signature = signer.sign(data)
            signatures.append(signature)

        aggregate_signature = SimpleSigner.aggregate_signatures(signatures)

    is_valid = SimpleSigner.verify_aggregate(identities, data, aggregate_signature, public_keys)
    
    if is_valid:
        store_data_in_mongo(data, aggregate_signature, identities)
        return jsonify({"message": "Aggregate signature valid and data stored"}), 200
    else:
        return jsonify({"error": "Aggregate signature invalid"}), 400

def store_data_in_mongo(data, aggregate_signature, identities):
    record = {
        'data': data.decode(),
        'aggregate_signature': aggregate_signature.hex(),
        'identities': identities
    }
    collection.insert_one(record)
    logger.info("Data and aggregate signature stored in MongoDB.")

@app.route('/list-routes', methods=['GET'])
def list_routes():
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(sorted(rule.methods))
        line = f"{rule.endpoint}: {methods} {rule}"
        output.append(line)
    return jsonify(output), 200

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(debug=True, host='0.0.0.0', port=8000)
