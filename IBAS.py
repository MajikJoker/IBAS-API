import logging
from flask import Blueprint, request, jsonify
import requests
from pymongo import MongoClient
import os
from utils import generate_key, encrypt_data, decrypt_data, get_hashed_data, check_hash
from datetime import datetime, timezone
# from verifier import SimpleSigner #used to have caps V

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define a Blueprint for ibas
ibas_routes = Blueprint('ibas_routes', __name__)

# Read environment variables for weather API URL, API key, MongoDB URI
WEATHER_API_URL = os.environ.get("WEATHER_API_URL")
WEATHER_API_KEY = os.environ.get("WEATHER_API_KEY")
MONGO_URI = os.environ.get("AZURE_COSMOS_CONNECTIONSTRING")

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.get_database('ibas-server')
collection = db.weather_records
keys_collection = db.transitKeys

@ibas_routes.before_app_first_request
def test_db_connection():
    try:
        client.admin.command('ping')
        logger.info("MongoDB connection established successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")

def fetch_and_store_weather():
    try:
        signers = []
        public_keys = []
        signatures = []

        identities = ["signer1", "signer2"]  # Example identities, should be dynamic
        for identity in identities:
            signer = SimpleSigner(identity)
            signer.generate_keys()
            signers.append(signer)
            public_keys.append(signer.public_key)

        data = b"weather_data"  # Example data, should be fetched weather data

        for signer in signers:
            signature = signer.sign(data)
            signatures.append(signature)

        aggregate_signature = SimpleSigner.aggregate_signatures(signatures)

        is_valid = SimpleSigner.verify_aggregate(identities, data, aggregate_signature, public_keys)
        
        if not is_valid:
            logger.warning("Aggregate signature is invalid, aborting weather fetch.")
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

        # Compute hash of the encrypted data
        data_hash = get_hashed_data(encrypted_data)
        logger.info(f"Data hash: {data_hash}")

        # Store encrypted data and hash in MongoDB
        record = {
            "name": "OpenWeather",
            "data": encrypted_data,
            "hash": data_hash
        }
        logger.info(f"Record to be inserted: {record}")

        try:
            result_record = collection.insert_one(record)
            logger.info(f"Inserted record ID: {result_record.inserted_id}")
        except Exception as e:
            logger.error(f"Error inserting record: {e}")

        try:
            result_key = keys_collection.insert_one({"key": key})
            logger.info(f"Inserted key ID: {result_key.inserted_id}")
        except Exception as e:
            logger.error(f"Error inserting key: {e}")
    except Exception as e:
        logger.exception("Exception occurred in fetch_and_store_weather: %s", e)
        raise

@ibas_routes.route('/fetch-weather', methods=['GET'])
def fetch_weather():
    try:
        fetch_and_store_weather()
        return jsonify({"message": "Weather data fetched and stored successfully"}), 200
    except Exception as e:
        logger.exception("Exception occurred")
        return jsonify({"error": "Internal Server Error"}), 500

@ibas_routes.route('/weather', methods=['POST'])
def get_weather():
    try:
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
    except Exception as e:
        logger.exception("Exception occurred in get_weather: %s", e)
        return jsonify({"error": "Internal Server Error"}), 500

@ibas_routes.route('/get-weather', methods=['GET'])
def get_stored_weather():
    try:
        record = collection.find_one()
        key_record = keys_collection.find_one()

        if not record or not key_record:
            return jsonify({"error": "No weather data available"}), 404

        encrypted_data = record["data"]
        stored_hash = record["hash"]
        key = key_record["key"]

        if not check_hash(encrypted_data, stored_hash):
            return jsonify({"error": "Data integrity compromised"}), 500

        weather_data = decrypt_data(encrypted_data, key)

        return jsonify(weather_data), 200
    except Exception as e:
        logger.exception("Exception occurred in get_stored_weather: %s", e)
        return jsonify({"error": "Internal Server Error"}), 500
