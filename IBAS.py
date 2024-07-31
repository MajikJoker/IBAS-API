import logging
from flask import Flask, request, jsonify
import requests
from pymongo import MongoClient
import os
import signal
import sys
from utils import generate_key, encrypt_data, decrypt_data, get_hashed_data, check_hash
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timezone
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Read environment variables for weather API URL, API key, MongoDB URI, and whether to fetch weather
WEATHER_API_URL = os.environ.get("WEATHER_API_URL")
WEATHER_API_KEY = os.environ.get("WEATHER_API_KEY")
MONGO_URI = os.environ.get("AZURE_COSMOS_CONNECTIONSTRING")
FETCH_WEATHER = os.environ.get("FETCH_WEATHER") == 'True'

# Function to test the MongoDB connection
@app.before_first_request
def test_db_connection():
    try:
        client.admin.command('ping')
        logger.info("MongoDB connection established successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.get_database('ibas-server')
weatherRecords = db.weather_records
keysCollection = db.transitKeys
customerDB = client.get_database('Customers')

class SimpleSigner:
    def __init__(self, identity):
        self.identity = identity  # Store the identity of the signer
        self.key = None  # Placeholder for the RSA private key
        self.public_key = None  # Placeholder for the RSA public key

    def generate_keys(self):
        self.key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
        self.public_key = self.key.publickey()  # Extract the public key

    def save_keys(self, private_key_file, public_key_file):
        with open(private_key_file, 'wb') as f:
            f.write(self.key.export_key())  # Save the private key to a file
        with open(public_key_file, 'wb') as f:
            f.write(self.public_key.export_key())  # Save the public key to a file

    def load_keys(self, private_key_file, public_key_file):
        with open(private_key_file, 'rb') as f:
            self.key = RSA.import_key(f.read())  # Load the private key from a file
        with open(public_key_file, 'rb') as f:
            self.public_key = RSA.import_key(f.read())  # Load the public key from a file

    def sign(self, data):
        message = self.identity + data.decode()  # Concatenate the identity with the string data
        h = SHA256.new(message.encode())  # Create a SHA-256 hash of the message
        signature = pkcs1_15.new(self.key).sign(h)  # Sign the hash with the private key
        return signature  # Return the signature

    def verify(self, identity, data, signature):
        message = identity.encode() + data  # Concatenate the identity with the data
        h = SHA256.new(message)  # Create a SHA-256 hash of the message
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)  # Verify the signature with the public key
            return True  # Return True if verification is successful
        except (ValueError, TypeError):
            return False  # Return False if verification fails

    @staticmethod
    def aggregate_signatures(signatures):
        return b''.join(signatures)  # Concatenate all signatures into one aggregate signature

@app.route('/setup', methods=['GET'])
def setup():
    username = request.args.get('username')
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    # Fetch collection name based on username
    collection_name = username
    
    # Check if collection exists (optional step)
    if collection_name not in customerDB.list_collection_names():
        return jsonify({"error": "Collection not found"}), 404
    
    # Fetch the data from the corresponding collection
    collection = customerDB[collection_name]
    document = collection.find_one()
    
    if not document:
        return jsonify({"error": "No data available"}), 404
    
    # Get all domain names and replace "__dot__" with "."
    domains = [domain.replace('__dot__', '.') for domain in document.get('domain', {}).keys()]
    
    # Generate keys for each domain and store them in a new collection named after the domain
    for domain in domains:
        signer = SimpleSigner(domain)
        signer.generate_keys()
        
        pem_collection_name = f"{domain}_PEM"
        pem_collection = customerDB[pem_collection_name]
        
        pem_data = {
            "domain": domain,
            "private_key": signer.key.export_key().decode(),
            "public_key": signer.public_key.export_key().decode()
        }
        
        pem_collection.insert_one(pem_data)
    
    return jsonify({"domains": domains}), 200

def fetch_and_store_weather():
    """
    Fetches weather data from the weather API, encrypts it, signs it, and stores it in MongoDB.
    """
    if not FETCH_WEATHER:
        logger.warning("FETCH_WEATHER is set to False")
        return

    response = requests.get(WEATHER_API_URL, params={"q": "London", "appid": WEATHER_API_KEY})
    if response.status_code != 200:
        logger.error(f"Failed to fetch weather data: {response.status_code}")
        return

    weather_data = response.json()
    weather_data['timestamp'] = datetime.now(timezone.utc).isoformat()
    logger.info(f"Fetched weather data: {weather_data}")

    # Encrypt the weather data
    key = generate_key()
    encrypted_data = encrypt_data(weather_data, key)
    logger.info(f"Encrypted data: {encrypted_data}")

    # Convert encrypted_data to a string if it's in bytes
    if isinstance(encrypted_data, bytes):
        encrypted_data = encrypted_data.decode()

    # Get all usernames dynamically
    usernames = [username for username in customerDB.list_collection_names() if not username.endswith('_PEM')]
    for username in usernames:
        # Fetch domains for the current username
        collection = customerDB[username]
        document = collection.find_one()
        
        if not document:
            logger.error(f"No document found for username {username}")
            continue

        domains = [domain.replace('__dot__', '.') for domain in document.get('domain', {}).keys()]
        
        signatures = []
        for domain in domains:
            pem_collection_name = f"{domain}_PEM"
            pem_collection = customerDB[pem_collection_name]
            pem_document = pem_collection.find_one({"domain": domain})
            
            private_key = RSA.import_key(pem_document["private_key"])
            signer = SimpleSigner(domain)
            signer.key = private_key
            signer.public_key = signer.key.publickey()
            signature = signer.sign(encrypted_data)
            signatures.append(signature)
        
        aggregate_signature = SimpleSigner.aggregate_signatures(signatures)
        
        # Store the aggregate signature in the user's collection
        try:
            collection.update_one({}, {"$set": {"agg_sig": aggregate_signature}})
            logger.info(f"Aggregate signature stored in {username} collection")
        except Exception as e:
            logger.error(f"Error updating {username} collection with aggregate signature: {e}")

    # Compute hash of the encrypted data
    data_hash = get_hashed_data(encrypted_data.encode())
    logger.info(f"Data hash: {data_hash}")

    # Store encrypted data and hash in weather_records collection
    record = {
        "data": encrypted_data,
        "hash": data_hash
    }
    logger.info(f"Record to be inserted: {record}")

    try:
        result_record = weatherRecords.insert_one(record)
        logger.info(f"Inserted record ID: {result_record.inserted_id}")
    except Exception as e:
        logger.error(f"Error inserting record: {e}")

    try:
        result_key = keysCollection.insert_one({"key": key})
        logger.info(f"Inserted key ID: {result_key.inserted_id}")
    except Exception as e:
        logger.error(f"Error inserting key: {e}")

@app.route('/fetch-weather', methods=['GET'])
def fetch_weather():
    try:
        if not FETCH_WEATHER:
            logger.warning("FETCH_WEATHER is set to False")
            return jsonify({"message": "Weather data fetch is disabled"}), 403

        fetch_and_store_weather()
        return jsonify({"message": "Weather data fetched and stored successfully"}), 200
    except Exception as e:
        logger.exception("Exception occurred")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/weather', methods=['POST'])
def get_weather():
    data = request.json
    latitude = data['latitude']
    longitude = data['longitude']

    params = {
        "lat": latitude,
        "lon": longitude,
        "appid": WEATHER_API_KEY
    }

    response = requests.get(WEATHER_API_URL, params=params)

    if response.status_code == 200:
        weather_data = response.json()
        return jsonify(weather_data)
    else:
        return jsonify({
            "error": f"API request failed with status code {response.status_code}",
            "message": response.text
        }), response.status_code

@app.route('/get-weather', methods=['GET'])
def get_stored_weather():
    record = weatherRecords.find_one()
    key_record = keysCollection.find_one()

    if not record or not key_record:
        return jsonify({"error": "No weather data available"}), 404

    encrypted_data = record["data"]
    stored_hash = record["hash"]
    key = key_record["key"]

    if not check_hash(encrypted_data.encode(), stored_hash):
        return jsonify({"error": "Data integrity compromised"}), 500

    weather_data = decrypt_data(encrypted_data.encode(), key)

    return jsonify(weather_data), 200

def handle_shutdown_signal(signum, frame):
    logger.info(f"Received shutdown signal ({signum}). Terminating gracefully.")
    scheduler.shutdown()  # Shutdown the scheduler gracefully
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_shutdown_signal)
signal.signal(signal.SIGINT, handle_shutdown_signal)

# Scheduler setup
scheduler = BackgroundScheduler()
scheduler.add_job(fetch_and_store_weather, 'interval', hours=1)
scheduler.start()

if __name__ == '__main__':
    logger.info("Starting Flask application")
    fetch_and_store_weather()  # Initial fetch
    app.run(debug=True, host='0.0.0.0', port=8000)

# Test route to manually trigger the fetch and store weather function
@app.route('/test-fetch-and-store-weather', methods=['GET'])
def test_fetch_and_store_weather():
    try:
        fetch_and_store_weather()
        return jsonify({"message": "Test fetch and store weather executed successfully"}), 200
    except Exception as e:
        logger.exception("Exception occurred during test")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

