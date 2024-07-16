from flask import Flask, request, jsonify
import requests
from pymongo import MongoClient
import os
from utils import generate_key, encrypt_data, decrypt_data, get_hashed_data, check_hash

app = Flask(__name__)

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Read environment variables for weather API URL, API key, MongoDB URI, and whether to fetch weather
WEATHER_API_URL = os.environ.get("WEATHER_API_URL")
WEATHER_API_KEY = os.environ.get("WEATHER_API_KEY")
MONGO_URI = os.environ.get("AZURE_COSMOS_CONNECTIONSTRING")
FETCH_WEATHER = os.environ.get("FETCH_WEATHER") == 'True'

# Set up MongoDB client and specify database and collections
client = MongoClient(MONGO_URI)
db = client.weather_data
collection = db.weather_records
keys_collection = db.transitKeys

@app.route('/fetch-weather', methods=['GET'])
def fetch_weather():
    """
    Fetches weather data from the external API and stores it in MongoDB.
    Returns an error if FETCH_WEATHER is set to False.
    Encrypts the weather data before storing it and also stores a hash of the encrypted data.
    """
    if not FETCH_WEATHER:
        return jsonify({"error": "Weather data fetch is disabled."}), 403
    
    response = requests.get(WEATHER_API_URL, params={"q": "London", "appid": WEATHER_API_KEY})
    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch weather data"}), 500
    
    weather_data = response.json()

    # Encrypt the weather data
    key = generate_key()
    encrypted_data = encrypt_data(weather_data, key)

    # Compute hash of the encrypted data
    data_hash = get_hashed_data(encrypted_data)
    
    # Store encrypted data and hash in MongoDB
    record = {
        "data": encrypted_data,
        "hash": data_hash
    }
    result_record = collection.insert_one(record)
    result_key = keys_collection.insert_one({"key": key})

    # Add debug prints
    print(f"Inserted record ID: {result_record.inserted_id}")
    print(f"Inserted key ID: {result_key.inserted_id}")

    return jsonify({"message": "Weather data fetched and stored successfully"}), 200

@app.route('/weather', methods=['POST'])
def get_weather():
    """
    Retrieves weather data from the external API based on provided latitude and longitude.
    """
    data = request.json
    latitude = data['latitude']
    longitude = data['longitude']
    
    params = {
        "lat": latitude,
        "lon": longitude,
        "appid": WEATHER_API_KEY
    }

    # Fetch weather data from external API using latitude and longitude
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
    """
    Retrieves the latest stored weather data from MongoDB.
    Decrypts the data and checks its integrity using the stored hash.
    Returns an error if no data is available or if data integrity is compromised.
    """
    # Find the latest record in the collection
    record = collection.find_one()
    key_record = keys_collection.find_one()
    
    if not record or not key_record:
        return jsonify({"error": "No weather data available"}), 404

    encrypted_data = record["data"]
    stored_hash = record["hash"]
    key = key_record["key"]

    # Check the integrity of the encrypted data
    if not check_hash(encrypted_data, stored_hash):
        return jsonify({"error": "Data integrity compromised"}), 500

    # Decrypt the weather data
    weather_data = decrypt_data(encrypted_data, key)

    return jsonify(weather_data), 200

if __name__ == '__main__':
    # Run the Flask app on the specified host and port
    app.run(debug=True, host='0.0.0.0', port=8000)
