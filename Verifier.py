import logging
from flask import Blueprint, request, jsonify
from pymongo import MongoClient
import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define a Blueprint for verifier
verifier_routes = Blueprint('verifier_routes', __name__)

# Read environment variables
MONGO_URI = os.environ.get("AZURE_COSMOS_CONNECTIONSTRING")

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.get_database('ibas-server')
keys_collection = db.transitKeys

class SimpleSigner:
    def __init__(self, identity):
        self.identity = identity
        self.key = None
        self.public_key = None

    def generate_keys(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def save_keys_to_db(self):
        keys_collection.update_one(
            {'identity': self.identity},
            {'$set': {
                'private_key': self.key.export_key().decode('utf-8'),
                'public_key': self.public_key.export_key().decode('utf-8')
            }},
            upsert=True
        )

    def load_keys_from_db(self):
        record = keys_collection.find_one({'identity': self.identity})
        if record:
            self.key = RSA.import_key(record['private_key'].encode('utf-8'))
            self.public_key = RSA.import_key(record['public_key'].encode('utf-8'))
        else:
            raise ValueError(f"Keys for identity '{self.identity}' not found in database.")

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

@verifier_routes.route('/setup-identity', methods=['POST'])
def setup_identity():
    try:
        identity = request.json.get('identity')
        if not identity:
            return jsonify({"error": "Identity is required"}), 400

        signer = SimpleSigner(identity)
        signer.generate_keys()
        signer.save_keys_to_db()
        return jsonify({"message": f"Keys for identity '{identity}' have been generated and stored in the database."}), 200
    except Exception as e:
        logger.exception("Exception occurred in setup_identity: %s", e)
        return jsonify({"error": "Internal Server Error"}), 500

@verifier_routes.route('/verify-signatures', methods=['POST'])
def verify_signatures():
    try:
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

        data = b"weather_data"  # Example data, should be fetched weather data

        for signer in signers:
            signature = signer.sign(data)
            signatures.append(signature)

        aggregate_signature = SimpleSigner.aggregate_signatures(signatures)

        is_valid = SimpleSigner.verify_aggregate(identities, data, aggregate_signature, public_keys)
        
        if is_valid:
            return jsonify({"message": "Aggregate signature valid"}), 200
        else:
            return jsonify({"error": "Aggregate signature invalid"}), 400
    except Exception as e:
        logger.exception("Exception occurred in verify_signatures: %s", e)
        return jsonify({"error": "Internal Server Error"}), 500