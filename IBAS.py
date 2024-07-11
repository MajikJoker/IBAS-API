import os
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from dotenv import load_dotenv
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# Load environment variables
load_dotenv()

# Debugging prints to verify environment variables
print("SECRET_KEY:", os.getenv('SECRET_KEY'))
print("MONGO_URI:", os.getenv('MONGO_URI'))

SECRET_KEY = os.getenv('SECRET_KEY')
MONGO_URI = os.getenv('MONGO_URI')

if not MONGO_URI:
    raise ValueError("No MONGO_URI found in environment variables")

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')

    source = request.json.get('source')

    # Store the keys in the MongoDB
    mongo.db.keys.insert_one({
        'source': source,
        'private_key': private_key,
        'public_key': public_key
    })

    return jsonify({'public_key': public_key, 'private_key': private_key}), 201

@app.route('/fetch_weather', methods=['POST'])
def fetch_weather():
    # Mock weather data fetch
    weather_data = {
        'temperature': 25,
        'humidity': 70
    }
    source = request.json.get('source')

    key_doc = mongo.db.keys.find_one({'source': source})
    private_key = RSA.import_key(key_doc['private_key'])
    signer = pkcs1_15.new(private_key)
    h = SHA256.new(str(weather_data).encode('utf-8'))
    signature = base64.b64encode(signer.sign(h)).decode('utf-8')

    return jsonify({'data': weather_data, 'signature': signature, 'public_key': key_doc['public_key']}), 200

@app.route('/store_data', methods=['POST'])
def store_data():
    data = request.json.get('data')
    signature = request.json.get('signature')
    public_key = request.json.get('public_key')
    source = request.json.get('source')

    h = SHA256.new(str(data).encode('utf-8'))
    hash_data = base64.b64encode(h.digest()).decode('utf-8')

    h_sig = SHA256.new(signature.encode('utf-8'))
    hash_sig = base64.b64encode(h_sig.digest()).decode('utf-8')

    mongo.db.weather_data.insert_one({
        'source': source,
        'data': data,
        'signature': signature,
        'public_key': public_key,
        'hash_data': hash_data,
        'hash_signature': hash_sig
    })

    return jsonify({'message': 'Data stored successfully'}), 201

@app.route('/verify_data', methods=['POST'])
def verify_data():
    source = request.json.get('source')
    data_doc = mongo.db.weather_data.find_one({'source': source})

    data = data_doc['data']
    signature = base64.b64decode(data_doc['signature'])
    public_key = RSA.import_key(data_doc['public_key'])

    # Verify data integrity
    h = SHA256.new(str(data).encode('utf-8'))
    hash_data = base64.b64encode(h.digest()).decode('utf-8')

    if hash_data != data_doc['hash_data']:
        return jsonify({'message': 'Data integrity compromised'}), 400

    # Verify signature integrity
    h_sig = SHA256.new(data_doc['signature'].encode('utf-8'))
    hash_sig = base64.b64encode(h_sig.digest()).decode('utf-8')

    if hash_sig != data_doc['hash_signature']:
        return jsonify({'message': 'Signature integrity compromised'}), 400

    # Verify the signature
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return jsonify({'message': 'Data is authentic and intact', 'data': data}), 200
    except (ValueError, TypeError):
        return jsonify({'message': 'Data verification failed'}), 400

if __name__ == '__main__':
    app.run(debug=True)
