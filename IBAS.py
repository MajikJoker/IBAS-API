import logging
from flask import Flask, request, jsonify
import requests
from pymongo import MongoClient
import os
import signal
import sys
import csv
from utils import generate_key, encrypt_data, decrypt_data, get_hashed_data, check_hash
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # This will allow all domains to access your Flask app

# Load environment variables from .env file
load_dotenv()

# Read environment variables for weather API URL, API key, MongoDB URI, and whether to fetch weather
OPENWEATHER_API_URL = os.environ.get("OPENWEATHER_API_URL")
OPENWEATHER_API_KEY = os.environ.get("OPENWEATHER_API_KEY")
MONGO_URI = os.environ.get("AZURE_COSMOS_CONNECTIONSTRING")
FETCH_WEATHER = os.environ.get("FETCH_WEATHER") == 'True'

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.get_database('ibas-server')
weatherRecords = db.weather_records
keysCollection = db.transitKeys
customerDB = client.get_database('Customers')

# Load capitals data from CSV
capitals_data = {}
with open('capitals.csv', mode='r', encoding='utf-8-sig') as infile:
    reader = csv.DictReader(infile)
    for row in reader:
        capital = row['capital'].strip().lower()
        lat = float(row['lat'])
        lon = float(row['lon'])
        capitals_data[capital] = (lat, lon)

# Function to test the MongoDB connection
@app.before_first_request
def test_db_connection():
    try:
        client.admin.command('ping')
        logger.info("MongoDB connection established successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")

class SimpleSigner:
    def __init__(self, identity):
        self.identity = identity
        self.key = None
        self.public_key = None

    def generate_keys(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def export_keys(self):
        return self.key.export_key().decode(), self.public_key.export_key().decode()

    def sign(self, data):
        message = self.identity.encode() + data
        h = SHA256.new(message)
        signature = pkcs1_15.new(self.key).sign(h)
        return signature

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

@app.route('/setup', methods=['GET'])
def setup():
    username = request.args.get('username')
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    collection_name = username
    
    if collection_name not in customerDB.list_collection_names():
        return jsonify({"error": "Collection not found"}), 404
    
    collection = customerDB[collection_name]
    document = collection.find_one()
    
    if not document:
        return jsonify({"error": "No data available"}), 404
    
    domains = [domain.replace('__dot__', '.') for domain in document.get('domain', {}).keys()]
    
    keys = {}
    for domain in domains:
        signer = SimpleSigner(domain)
        signer.generate_keys()
        pri_key, pub_key = signer.export_keys()  # Switched the order here to correct the labeling
        keys[f'pub_{domain.replace(".", "__dot__")}_PEM'] = pub_key
        keys[f'pri_{domain.replace(".", "__dot__")}_PEM'] = pri_key
    
    collection.update_one({'_id': document['_id']}, {'$set': keys})
    
    return jsonify({"domains": domains, "keys": keys}), 200

def fetch_and_store_weather(capital=None):
    """
    Fetches weather data from the weather API, encrypts it, signs it, and stores it in MongoDB.
    """
    if not FETCH_WEATHER:
        logger.warning("FETCH_WEATHER is set to False")
        return False

    if capital:
        capital = capital.strip().lower()
        location = capitals_data.get(capital)
        if not location:
            logger.error("Capital not found")
            return False
        lat, lon = location
    else:
        logger.error("No capital provided")
        return False

    params = {
        "lat": lat,
        "lon": lon,
        "appid": OPENWEATHER_API_KEY
    }
    response = requests.get(OPENWEATHER_API_URL, params=params)
    if response.status_code != 200:
        logger.error(f"Failed to fetch weather data: {response.status_code}")
        return False

    weather_data = response.json()
    weather_data['timestamp'] = datetime.now(timezone.utc).isoformat()
    logger.info(f"Fetched weather data: {weather_data}")

    # Encrypt the weather data
    key = generate_key()
    encrypted_data = encrypt_data(weather_data, key)
    logger.info(f"Encrypted data: {encrypted_data}")

    # Compute hash of the encrypted data
    data_hash = get_hashed_data(encrypted_data)
    logger.info(f"Data hash: {data_hash}")

    # Load keys and sign data
    domain_docs = customerDB.WeatherNodeInitiative.find_one() # This is weathernode initiative
    domains = domain_docs.get('domain', {}).keys() # Getting the 3 domains
    identities = []
    signatures = []
    public_keys = []
    is_valid = False  # Default value for is_valid

    try:
        for domain in domains:
            signer = SimpleSigner(domain)
            pri_key = domain_docs.get(f'pri_{domain}_PEM')
            pub_key = domain_docs.get(f'pub_{domain}_PEM')
            
            signer.key = RSA.import_key(pri_key.encode())
            signer.public_key = RSA.import_key(pub_key.encode())

            signature = signer.sign(encrypted_data.encode())
            signatures.append(signature)
            identities.append(domain)
            public_keys.append(signer.public_key)

        agg_sig = SimpleSigner.aggregate_signatures(signatures)

        # Store encrypted data, hash, and aggregate signature in MongoDB
        record = {
            "data": encrypted_data,
            "hash": data_hash,
            "agg_sig": agg_sig.hex()  # Store as hex string
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

        # Verify the aggregate signature
        is_valid = SimpleSigner.verify_aggregate(identities, encrypted_data.encode(), agg_sig, public_keys)
        logger.info(f"Aggregate signature valid: {is_valid}")
    except (ValueError, TypeError) as e:
        logger.error(f"Error in key processing or verification: {e}")
        is_valid = False

    return is_valid

@app.route('/fetch-weather', methods=['GET'])
def fetch_weather():
    try:
        capital = request.args.get('capital', None)
        if not FETCH_WEATHER:
            logger.warning("FETCH_WEATHER is set to False")
            return jsonify({"message": "Weather data fetch is disabled"}), 403

        is_valid = fetch_and_store_weather(capital)
        if is_valid:
            return jsonify({"message": "Weather data fetched and stored successfully", "valid": is_valid}), 200
        else:
            return jsonify({"message": "Weather data fetched but signature invalid or capital not found", "valid": is_valid}), 500
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
        "appid": OPENWEATHER_API_KEY
    }

    response = requests.get(OPENWEATHER_API_URL, params=params)

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

    if not check_hash(encrypted_data, stored_hash):
        return jsonify({"error": "Data integrity compromised"}), 500

    weather_data = decrypt_data(encrypted_data, key)

    return jsonify(weather_data), 200

def handle_shutdown_signal(signum, frame):
    logger.info(f"Received shutdown signal ({signum}). Terminating gracefully.")
    scheduler.shutdown()  # Shutdown the scheduler gracefully
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_shutdown_signal)
signal.signal(signal.SIGINT, handle_shutdown_signal)

# Scheduler setup
scheduler = BackgroundScheduler()
scheduler.add_job(fetch_and_store_weather, 'interval', hours=48)
scheduler.start()

if __name__ == '__main__':
    logger.info("Starting Flask application")
    fetch_and_store_weather()  # Initial fetch
    app.run(debug=True, host='0.0.0.0', port=8000)
