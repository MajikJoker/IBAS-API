from flask import Flask, request, jsonify
import requests
from pymongo import MongoClient
import os
from utils import generate_key, encrypt_data, decrypt_data, get_hashed_data, check_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import logging
import signal
import sys

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Read environment variables for weather API URL, API key, MongoDB URI, and whether to fetch weather
WEATHER_API_URL = os.environ.get("WEATHER_API_URL")
WEATHER_API_KEY = os.environ.get("WEATHER_API_KEY")
MONGO_URI = os.environ.get("AZURE_COSMOS_CONNECTIONSTRING")
FETCH_WEATHER = os.environ.get("FETCH_WEATHER") == 'True'

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.get_database('ibas-server')  # Ensure the database name is fetched correctly
collection = db.weather_records
keys_collection = db.transitKeys

# Function to test the MongoDB connection
@app.before_first_request
def test_db_connection():
    try:
        client.admin.command('ping')
        logger.info("MongoDB connection established successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")

def fetch_and_store_weather():
    """
    Function to fetch weather data and store it in MongoDB.
    """
    try:
        response = requests.get(WEATHER_API_URL, params={"q": "London", "appid": WEATHER_API_KEY})
        if response.status_code != 200:
            logger.error(f"Failed to fetch weather data: {response.status_code}")
            return

        weather_data = response.json()
        logger.debug(f"Fetched weather data: {weather_data}")

        # Encrypt the weather data
        key = generate_key()
        encrypted_data = encrypt_data(weather_data, key)
        logger.debug(f"Encrypted data: {encrypted_data}")

        # Compute hash of the encrypted data
        data_hash = get_hashed_data(encrypted_data)
        logger.debug(f"Data hash: {data_hash}")

        # Store encrypted data and hash in MongoDB
        record = {
            "data": encrypted_data,
            "hash": data_hash
        }
        logger.debug(f"Record to be inserted: {record}")

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
        logger.error(f"Exception occurred: {e}")

# Initialize and start the scheduler
scheduler = BackgroundScheduler()
if FETCH_WEATHER:
    scheduler.add_job(
        func=fetch_and_store_weather,
        trigger=IntervalTrigger(hours=1),
        id='weather_fetch_job',
        name='Fetch weather data every hour',
        replace_existing=True)
    scheduler.start()
    logger.info("Scheduler started and job added to fetch weather data every hour.")

@app.route('/fetch-weather', methods=['GET'])
def fetch_weather():
    try:
        if not FETCH_WEATHER:
            logger.info("FETCH_WEATHER is set to False")
            return jsonify({"error": "Weather data fetch is disabled."}), 403

        fetch_and_store_weather()
        return jsonify({"message": "Weather data fetched and stored successfully"}), 200
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

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

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint to ensure the application is running.
    """
    return "Healthy", 200

def handle_shutdown_signal(signum, frame):
    logger.info(f"Received shutdown signal ({signum}). Terminating gracefully.")
    scheduler.shutdown()
    sys.exit(0)

# Register shutdown signal handlers
signal.signal(signal.SIGTERM, handle_shutdown_signal)
signal.signal(signal.SIGINT, handle_shutdown_signal)

if __name__ == '__main__':
    # Run the Flask app on the specified host and port
    logger.info("Starting Flask application.")
    app.run(debug=True, host='0.0.0.0', port=8000)
