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
from flask_cors import CORS
import uuid
from datetime import timedelta
from bson import ObjectId
from functools import wraps

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
TOMORROWIO_API_KEY = os.environ.get("TOMORROWIO_API_KEY")
TOMORROWIO_API_URL = os.environ.get("TOMORROWIO_API_URL")
VISUALCROSSING_API_KEY = os.environ.get("VISUALCROSSING_API_KEY")
VISUALCROSSING_API_URL = os.environ.get("VISUALCROSSING_API_URL")
MONGO_URI = os.environ.get("AZURE_COSMOS_CONNECTIONSTRING")

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.get_database('ibas-server')
weatherRecords = db.weather_records
customerDB = client.get_database('Customers')

# Transit Key Database Setup
transit_key_db = client.get_database('Transit_Key')

# Load capitals data from CSV
capitals_data = {}
with open('capitals.csv', mode='r', encoding='utf-8-sig') as infile:
    reader = csv.DictReader(infile)
    for row in reader:
        capital = row['capital'].strip().lower()
        lat = float(row['lat'])
        lon = float(row['lon'])
        capitals_data[capital] = (lat, lon)

def is_within_margin(value1, value2, margin):
    if value1 == 0 and value2 == 0:
        return True  # Both values are zero, so they are equal
    return abs(value1 - value2) / max(value1, value2) <= margin

def check_weather_data_consistency(data):
    margins = {
        "temperature": 0.2,  # 20%
        "humidity": 0.4,     # 40%
        "pressure": 0.2,     # 20%
        "windSpeed": 0.5,    # 50%
        "cloudCover": 0.3,   # 30%
        "precipitation": 1.0 # 100%
    }

    tomorrowio = data['tomorrowio']
    visualcrossing = data['visualcrossing']
    openweather = data['openweather']

    sources = {
        'tomorrowio': tomorrowio,
        'visualcrossing': visualcrossing,
        'openweather': openweather
    }

    fields = ["temperature", "humidity", "pressure", "windSpeed", "cloudCover", "precipitation"]

    valid_data = {}

    for field in fields:
        values = {source: sources[source][field] for source in sources}

        # Check if all three values are within the margin
        all_within_margin = (
            is_within_margin(values['tomorrowio'], values['visualcrossing'], margins[field]) and
            is_within_margin(values['tomorrowio'], values['openweather'], margins[field]) and
            is_within_margin(values['visualcrossing'], values['openweather'], margins[field])
        )

        if all_within_margin:
            # If all three are within the margin, average all three
            valid_data[field] = list(values.values())
            logger.info(f"All sources within margin for field {field}. Using all values.")
        else:
            # Otherwise, calculate deviations and exclude the outlier
            deviations = {}
            for source_name, value in values.items():
                deviation_sum = 0
                for other_source_name, other_value in values.items():
                    if source_name != other_source_name:
                        deviation_sum += abs(value - other_value)
                deviations[source_name] = deviation_sum

            # Identify the outlier as the one with the maximum deviation
            outlier = max(deviations, key=deviations.get)
            consistent_values = [value for source, value in values.items() if source != outlier]

            # Log the exclusion of the outlier
            logger.info(f"Excluding outlier {outlier} with value {values[outlier]} for field {field}.")

            # Store the consistent values for averaging
            valid_data[field] = consistent_values

    return True, valid_data  # Always return True since we're retaining all fields

# Function to validate API keys and check permissions
def validate_api_key(permission_required):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.args.get('apikey')
            if not api_key:
                return jsonify({"error": "API key is required"}), 401

            # Check in Admin collection first
            admin_doc = db.Admin_API_Keys.find_one({"admins.api_key": api_key})
            if admin_doc:
                admin = next((admin for admin in admin_doc['admins'] if admin['api_key'] == api_key), None)
                if admin and permission_required in admin['permissions']:
                    return f(*args, **kwargs)
                else:
                    return jsonify({"error": "Permission denied"}), 403
            
            # If not found in Admin, check in Client collection
            client_doc = db.Customer_API_Keys.find_one({"clients.api_key": api_key})
            if client_doc:
                client = next((client for client in client_doc['clients'] if client['api_key'] == api_key), None)
                if client and permission_required in client['permissions']:
                    return f(*args, **kwargs)
                else:
                    return jsonify({"error": "Permission denied"}), 403

            return jsonify({"error": "Invalid API key"}), 401
        return decorated_function
    return decorator

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
@validate_api_key(permission_required='setup')
def setup():
    username = request.args.get('username')
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    # Find the correct document that stores the "clients" array
    client_document = db.Customer_API_Keys.find_one({"clients.client_name": username})
    
    if not client_document:
        # If the client doesn't exist, create a new entry in the "clients" array
        client_document = {
            "_id": ObjectId(),  # Generate a new ObjectId for the document
            "clients": []
        }
    
    # Check if the client already exists in the "clients" array
    existing_client = None
    for client in client_document["clients"]:
        if client["client_name"] == username:
            existing_client = client
            break
    
    if existing_client:
        return jsonify({"error": "Client already exists"}), 400

    # Generate API keys and keys for domains
    collection = customerDB[username]
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
    
    # Update the collection with the new keys
    collection.update_one({'_id': document['_id']}, {'$set': keys})
    
    # Generate API key for the customer
    api_key = str(uuid.uuid4())  # Generate a random UUID as the API key
    
    # Define the current time and expiry date (1 year from now)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=365)
    
    # Create the new client object
    new_client = {
        "client_name": username,
        "api_key": api_key,
        "permissions": ["get-weather"],
        "usage_limit": 1000,
        "requests_made": 0,
        "created_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat()
    }
    
    # Append the new client to the "clients" array
    client_document["clients"].append(new_client)
    
    # Update the document in MongoDB
    db.Customer_API_Keys.update_one(
        {"_id": client_document["_id"]}, 
        {"$set": {"clients": client_document["clients"]}},
        upsert=True
    )
    
    return jsonify({"domains": domains, "keys": keys, "api_key": api_key}), 200

def fetch_weather_openweather(lat, lon):
    params = {
        "lat": lat,
        "lon": lon,
        "appid": OPENWEATHER_API_KEY,
        "units": "metric"
    }
    response = requests.get(OPENWEATHER_API_URL, params=params)
    if response.status_code == 200:
        data = response.json()
        simplified_data = {
            "temperature": data["main"]["temp"],
            "temperatureApparent": data["main"]["feels_like"],
            "humidity": data["main"]["humidity"],
            "pressure": data["main"]["pressure"],
            "windSpeed": data["wind"]["speed"],
            "cloudCover": data["clouds"]["all"],
            "precipitation": data.get("rain", {}).get("1h", 0)
        }
        return simplified_data
    else:
        logger.error(f"OpenWeather API request failed with status code {response.status_code}")
        return None

def fetch_weather_tomorrowio(lat, lon):
    params = {
        "location": f"{lat},{lon}",
        "apikey": TOMORROWIO_API_KEY,
        "units": "metric"
    }
    response = requests.get(TOMORROWIO_API_URL, params=params)
    if response.status_code == 200:
        data = response.json()
        simplified_data = {
            "temperature": data['timelines']['minutely'][0]['values']['temperature'],
            "temperatureApparent": data['timelines']['minutely'][0]['values']['temperatureApparent'],
            "humidity": data['timelines']['minutely'][0]['values']['humidity'],
            "pressure": data['timelines']['minutely'][0]['values']['pressureSurfaceLevel'],
            "windSpeed": data['timelines']['minutely'][0]['values']['windSpeed'],
            "cloudCover": data['timelines']['minutely'][0]['values']['cloudCover'],
            "precipitation": data['timelines']['minutely'][0]['values']['rainIntensity']
        }
        return simplified_data
    else:
        logger.error(f"Tomorrow.io API request failed with status code {response.status_code}")
        return None

def fetch_weather_visualcrossing(lat, lon):
    params = {
        "location": f"{lat},{lon}",
        "key": VISUALCROSSING_API_KEY,
        "unitGroup": "metric"
    }
    response = requests.get(VISUALCROSSING_API_URL, params=params)
    if response.status_code == 200:
        data = response.json()
        day = data['days'][0]
        simplified_data = {
            "temperature": day['temp'],
            "temperatureApparent": day['feelslike'],
            "humidity": day['humidity'],
            "pressure": day['pressure'],
            "windSpeed": day['windspeed'],
            "cloudCover": day['cloudcover'],
            "precipitation": day['precip']
        }
        return simplified_data
    else:
        logger.error(f"VisualCrossing API request failed with status code {response.status_code}")
        return None
    
def fetch_and_store_weather(capital=None, client_name=None):

    if capital:
        capital = capital.strip().lower()
        location = capitals_data.get(capital)
        if not location:
            logger.error(f"Capital '{capital}' not found")
            return False
        lat, lon = location
        logger.info(f"Capital '{capital}' found with coordinates: {lat}, {lon}")
    else:
        logger.error("No capital provided")
        return False

    weather_data_openweather = fetch_weather_openweather(lat, lon)
    weather_data_tomorrowio = fetch_weather_tomorrowio(lat, lon)
    weather_data_visualcrossing = fetch_weather_visualcrossing(lat, lon)

    if not weather_data_openweather or not weather_data_tomorrowio or not weather_data_visualcrossing:
        logger.error("Failed to fetch weather data from one or more APIs")
        return False

    weather_data = {
        "openweather": weather_data_openweather,
        "tomorrowio": weather_data_tomorrowio,
        "visualcrossing": weather_data_visualcrossing,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    logger.info(f"Fetched weather data: {weather_data}")

    is_consistent, valid_data = check_weather_data_consistency(weather_data)

    # Calculate averages for consistent fields and round them to 2 decimal places
    averages = {field: round(sum(values) / len(values), 2) for field, values in valid_data.items()}
    logger.info(f"Averages computed: {averages}")

    # Generate and encrypt the transit key
    transit_key = generate_key()
    encrypted_transit_key = encrypt_data(transit_key, transit_key)  # Encrypt with itself or another suitable method
    logger.info(f"Generated and encrypted transit key")

    # Store the encrypted transit key in the new Transit_Key database
    transit_key_collection = transit_key_db[f"{client_name}_transitKeys"]
    transit_key_collection.update_one(
        {"client_name": client_name},
        {"$set": {"key": encrypted_transit_key}},
        upsert=True
    )
    logger.info(f"Stored encrypted transit key for client '{client_name}' in Transit_Key database")

    # Encrypt the weather data using the transit key
    encrypted_data = encrypt_data(averages, transit_key)
    logger.info(f"Encrypted weather data: {encrypted_data}")

    data_hash = get_hashed_data(encrypted_data)
    logger.info(f"Data hash: {data_hash}")

    domain_docs = customerDB[client_name].find_one()
    if not domain_docs:
        logger.error(f"No domain documents found for client '{client_name}'")
        return False
    
    domains = domain_docs.get('domain', {}).keys()
    if not domains:
        logger.error(f"No domains found in domain documents for client '{client_name}'")
        return False

    identities = []
    signatures = []
    public_keys = []
    is_valid = False

    try:
        for domain in domains:
            signer = SimpleSigner(domain)
            pri_key = domain_docs.get(f'pri_{domain}_PEM')
            pub_key = domain_docs.get(f'pub_{domain}_PEM')

            if not pri_key or not pub_key:
                logger.error(f"Private or public key not found for domain '{domain}'")
                return False

            signer.key = RSA.import_key(pri_key.encode())
            signer.public_key = RSA.import_key(pub_key.encode())

            signature = signer.sign(encrypted_data.encode())
            signatures.append(signature)
            identities.append(domain)
            public_keys.append(signer.public_key)

        agg_sig = SimpleSigner.aggregate_signatures(signatures)
        logger.info(f"Aggregate signature created")

        # Insert the record into the specific user's collection
        user_db = client.get_database('Weather_Record')
        user_collection = user_db[f'{client_name}_Data']

        record = {
            "data": encrypted_data,
            "hash": data_hash,
            "agg_sig": agg_sig.hex(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        logger.info(f"Record to be inserted: {record}")

        try:
            result_record = user_collection.insert_one(record)
            logger.info(f"Inserted record ID: {result_record.inserted_id}")
        except Exception as e:
            logger.error(f"Error inserting record into user's collection: {e}")

        is_valid = SimpleSigner.verify_aggregate(identities, encrypted_data.encode(), agg_sig, public_keys)
        logger.info(f"Aggregate signature valid: {is_valid}")
    except (ValueError, TypeError) as e:
        logger.error(f"Error in key processing or verification: {e}")
        is_valid = False

    return is_valid

@app.route('/fetch-weather', methods=['GET'])
@validate_api_key(permission_required='fetch-weather')
def fetch_weather():
    try:
        capital = request.args.get('capital', None)
        api_key = request.args.get('apikey', None)

        if capital:
            # Normalize the capital name by stripping extra spaces and replacing multiple spaces with a single space
            capital = ' '.join(capital.split())

        if not api_key:
            logger.error("API key is required")
            return jsonify({"error": "API key is required"}), 400

        # Look up the client_name associated with the given API key
        client_document = db.Customer_API_Keys.find_one({"clients.api_key": api_key})
        if not client_document:
            logger.error("Invalid API key provided")
            return jsonify({"error": "Invalid API key"}), 401

        client = next((client for client in client_document['clients'] if client['api_key'] == api_key), None)
        if not client:
            logger.error("Client not found for the provided API key")
            return jsonify({"error": "Client not found"}), 401

        client_name = client['client_name']

        # Fetch and store weather data, generate and store the transit key
        is_valid = fetch_and_store_weather(capital, client_name)
        if is_valid:
            logger.info(f"Weather data for capital '{capital}' fetched and stored successfully for client '{client_name}'")
            return jsonify({"message": "Weather data fetched and stored successfully", "valid": is_valid}), 200
        else:
            logger.warning(f"Weather data for capital '{capital}' fetched but signature invalid or capital not found")
            return jsonify({"message": "Weather data fetched but signature invalid or capital not found", "valid": is_valid}), 500
    except Exception as e:
        logger.exception("Exception occurred")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/fetch-only', methods=['GET'])
@validate_api_key(permission_required='get-weather')
def fetch_only():
    try:
        capital = request.args.get('capital', None)
        
        if capital:
            # Normalize the capital name by stripping extra spaces and replacing multiple spaces with a single space
            capital = ' '.join(capital.split())

        if not capital:
            logger.error("No capital provided")
            return jsonify({"error": "Capital is required"}), 400

        location = capitals_data.get(capital.lower())
        if not location:
            logger.error(f"Capital '{capital}' not found")
            return jsonify({"error": f"Capital '{capital}' not found"}), 404

        lat, lon = location
        logger.info(f"Capital '{capital}' found with coordinates: {lat}, {lon}")

        weather_data_openweather = fetch_weather_openweather(lat, lon)
        weather_data_tomorrowio = fetch_weather_tomorrowio(lat, lon)
        weather_data_visualcrossing = fetch_weather_visualcrossing(lat, lon)

        if not weather_data_openweather or not weather_data_tomorrowio or not weather_data_visualcrossing:
            logger.error("Failed to fetch weather data from one or more APIs")
            return jsonify({"error": "Failed to fetch weather data from one or more APIs"}), 500

        weather_data = {
            "openweather": weather_data_openweather,
            "tomorrowio": weather_data_tomorrowio,
            "visualcrossing": weather_data_visualcrossing,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        logger.info(f"Fetched weather data: {weather_data}")

        is_consistent, valid_data = check_weather_data_consistency(weather_data)

        # Calculate averages for consistent fields and round them to 2 decimal places
        averages = {field: round(sum(values) / len(values), 2) for field, values in valid_data.items()}
        logger.info(f"Averages computed: {averages}")

        return jsonify({"averages": averages, "valid": is_consistent}), 200
    except Exception as e:
        logger.exception("Exception occurred")
        return jsonify({"error": "Internal Server Error"}), 500

def handle_shutdown_signal(signum, frame):
    logger.info(f"Received shutdown signal ({signum}). Terminating gracefully.")
    scheduler.shutdown()  # Shutdown the scheduler gracefully
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_shutdown_signal)
signal.signal(signal.SIGINT, handle_shutdown_signal)

# Scheduler setup
scheduler = BackgroundScheduler()
scheduler.add_job(fetch_and_store_weather, 'interval', hours=12, kwargs={'capital': 'Singapore'})  # Example with 'Singapore'
scheduler.start()

if __name__ == '__main__':
    logger.info("Starting Flask application")
    fetch_and_store_weather()  # Initial fetch
    app.run(debug=True, host='0.0.0.0', port=8000)
