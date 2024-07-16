from flask import Flask, request, jsonify
import requests
from pymongo import MongoClient
import os
import hashlib
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from utils import generate_key, encrypt_data, decrypt_data, get_hashed_data, check_hash

app = Flask(__name__)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

WEATHER_API_URL = os.getenv("WEATHER_API_URL")
MONGO_URI = os.getenv("MONGO_URI")
FETCH_WEATHER = os.getenv("FETCH_WEATHER") == 'True'

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.weather_data
collection = db.weather_records
keys_collection = db.transitKeys

@app.route('/fetch-weather', methods=['GET'])
def fetch_weather():
    if not FETCH_WEATHER:
        return jsonify({"error": "Weather data fetch is disabled."}), 403
    
    response = requests.get(WEATHER_API_URL)
    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch weather data"}), 500
    
    weather_data = response.json()

    # Encrypt weather data
    key = generate_key()
    encrypted_data = encrypt_data(weather_data, key)

    # Store encrypted data and hash in MongoDB
    data_hash = get_hashed_data(encrypted_data)
    record = {
        "data": encrypted_data,
        "hash": data_hash
    }
    collection.insert_one(record)
    keys_collection.insert_one({"key": key})

    return jsonify({"message": "Weather data fetched and stored successfully"}), 200

@app.route('/get-weather', methods=['GET'])
def get_weather():
    record = collection.find_one()
    key_record = keys_collection.find_one()
    if not record or not key_record:
        return jsonify({"error": "No weather data available"}), 404

    encrypted_data = record["data"]
    stored_hash = record["hash"]
    key = key_record["key"]

    # Verify data integrity
    if not check_hash(encrypted_data, stored_hash):
        return jsonify({"error": "Data integrity compromised"}), 500

    # Decrypt weather data
    weather_data = decrypt_data(encrypted_data, key)

    return jsonify(weather_data), 200

if __name__ == '__main__':
    app.run(debug=True)
