import unittest
from IBAS import app, db
from unittest.mock import patch
from pymongo import MongoClient
import json

class TestEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up the test client and other configurations before running any tests."""
        cls.app = app.test_client()
        cls.app.testing = True

    def setUp(self):
        """Mock the database connection for each test."""
        self.patcher = patch('IBAS.db', spec=True)  # Use spec=True to prevent autospec issues
        self.mock_db = self.patcher.start()

        # Mock MongoDB collections
        self.mock_admin_collection = self.mock_db.Admin_API_Keys
        self.mock_customer_collection = self.mock_db.Customer_API_Keys
        self.mock_weather_collection = self.mock_db.Weather_Record
        self.mock_transit_key_collection = self.mock_db.Transit_Key

    def tearDown(self):
        """Stop the mock patcher after each test."""
        self.patcher.stop()

    def test_setup_endpoint_valid(self):
        """Test the /setup endpoint with valid data."""
        mock_client_name = 'testuser'
        self.mock_customer_collection.find_one.return_value = {
            '_id': 'some_id',
            'clients': []
        }

        with patch('IBAS.uuid.uuid4', return_value='mock_uuid'):
            response = self.app.get(f'/setup?apikey=valid_api_key&username={mock_client_name}')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("domains", response.json)
        self.assertIn("keys", response.json)
        self.assertIn("api_key", response.json)

    def test_setup_endpoint_no_username(self):
        """Test the /setup endpoint without providing a username."""
        response = self.app.get('/setup?apikey=valid_api_key')
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error"], "Username is required")

    def test_fetch_store_weather_valid(self):
        """Test the /fetch-store-weather endpoint with valid parameters."""
        with patch('IBAS.fetch_and_store_weather', return_value=True):
            response = self.app.get('/fetch-store-weather?capital=paris&apikey=valid_api_key')

        self.assertEqual(response.status_code, 200)
        self.assertIn("message", response.json)
        self.assertTrue(response.json["valid"])

    def test_fetch_store_weather_invalid_key(self):
        """Test the /fetch-store-weather endpoint with an invalid API key."""
        self.mock_customer_collection.find_one.return_value = None
        
        response = self.app.get('/fetch-store-weather?capital=paris&apikey=invalid_api_key')
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error"], "Invalid API key")

    def test_get_historical_data_valid(self):
        """Test the /get-historical-data endpoint with valid API key."""
        self.mock_customer_collection.find_one.return_value = {
            'clients': [{'client_name': 'testclient', 'api_key': 'valid_api_key'}]
        }

        mock_weather_data = [
            {"_id": "some_id_1", "data": "encrypted_data_1", "hash": "hash_1", "timestamp": "2024-08-23T12:00:00Z"},
            {"_id": "some_id_2", "data": "encrypted_data_2", "hash": "hash_2", "timestamp": "2024-08-24T12:00:00Z"}
        ]
        
        with patch('IBAS.decrypt_data', side_effect=["{\"temperature\": 25}", "{\"temperature\": 26}"]):
            with patch('IBAS.check_hash', return_value=True):
                self.mock_db.Weather_Record.testclient_Data.find.return_value = mock_weather_data
                
                response = self.app.get('/get-historical-data?apikey=valid_api_key')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("historical_data", response.json)
        self.assertEqual(len(response.json["historical_data"]), 2)

    def test_get_historical_data_invalid_key(self):
        """Test the /get-historical-data endpoint with an invalid API key."""
        self.mock_customer_collection.find_one.return_value = None
        
        response = self.app.get('/get-historical-data?apikey=invalid_api_key')
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error"], "Invalid API key")

if __name__ == '__main__':
    unittest.main()
