import unittest
from IBAS import app, db
from unittest.mock import patch, MagicMock

class TestEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = app.test_client()
        cls.app.testing = True

    def setUp(self):
        """Mock the database connection for each test."""
        self.mock_admin_collection = MagicMock()
        self.mock_customer_collection = MagicMock()
        self.mock_weather_collection = MagicMock()
        self.mock_transit_key_collection = MagicMock()

        self.patcher_db = patch('IBAS.db', autospec=True)
        self.mock_db = self.patcher_db.start()

        self.mock_db.Admin_API_Keys = self.mock_admin_collection
        self.mock_db.Customer_API_Keys = self.mock_customer_collection
        self.mock_db.Weather_Record = MagicMock()
        self.mock_db.Transit_Key = self.mock_transit_key_collection

        self.mock_db.Weather_Record.testclient_Data = MagicMock()

        # Set up the mock response for find_one on Admin_API_Keys
        self.mock_admin_collection.find_one.return_value = {
            '_id': 'some_id',
            'admins': [{
                'admin_name': 'IBAS_API',
                'api_key': '123',
                'permissions': ['setup', 'fetch-store-weather', 'get-historical-data', 'fetch-only']
            }]
        }

        # Set up the mock response for find_one on Customer_API_Keys
        self.mock_customer_collection.find_one.return_value = {
            '_id': 'some_id',
            'clients': [{
                'client_name': 'WeatherNodeInitiative',
                'api_key': '58c8f6da-98b4-4c4b-bfa7-5b52f09ea139',
                'permissions': ['setup', 'fetch-store-weather', 'get-historical-data', 'fetch-only']
            }]
        }

    def tearDown(self):
        self.patcher_db.stop()

    def test_setup_endpoint_valid(self):
        mock_client_name = 'WeatherNodeInitiative'

        with patch('IBAS.uuid.uuid4', return_value='mock_uuid'):
            response = self.app.get(f'/setup?apikey=58c8f6da-98b4-4c4b-bfa7-5b52f09ea139&username={mock_client_name}')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("domains", response.json)
        self.assertIn("keys", response.json)
        self.assertIn("api_key", response.json)

    def test_setup_endpoint_no_username(self):
        response = self.app.get('/setup?apikey=58c8f6da-98b4-4c4b-bfa7-5b52f09ea139')
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error"], "Username is required")

    def test_fetch_store_weather_valid(self):
        with patch('IBAS.fetch_and_store_weather', return_value=True):
            response = self.app.get('/fetch-store-weather?capital=paris&apikey=58c8f6da-98b4-4c4b-bfa7-5b52f09ea139')
        self.assertEqual(response.status_code, 200)
        self.assertIn("message", response.json)
        self.assertTrue(response.json["valid"])

    def test_fetch_store_weather_invalid_key(self):
        self.mock_customer_collection.find_one.return_value = None
        response = self.app.get('/fetch-store-weather?capital=paris&apikey=invalid_api_key')
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error"], "Invalid API key")

    def test_get_historical_data_valid(self):
        mock_weather_data = [
            {"_id": "some_id_1", "data": "encrypted_data_1", "hash": "hash_1", "timestamp": "2024-08-23T12:00:00Z"},
            {"_id": "some_id_2", "data": "encrypted_data_2", "hash": "hash_2", "timestamp": "2024-08-24T12:00:00Z"}
        ]
        
        with patch('IBAS.decrypt_data', side_effect=["{\"temperature\": 25}", "{\"temperature\": 26}"]):
            with patch('IBAS.check_hash', return_value=True):
                self.mock_db.Weather_Record.testclient_Data.find.return_value = mock_weather_data
                response = self.app.get('/get-historical-data?apikey=58c8f6da-98b4-4c4b-bfa7-5b52f09ea139')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("historical_data", response.json)
        self.assertEqual(len(response.json["historical_data"]), 2)

    def test_get_historical_data_invalid_key(self):
        self.mock_customer_collection.find_one.return_value = None
        response = self.app.get('/get-historical-data?apikey=invalid_api_key')
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error"], "Invalid API key")

    def test_setup_endpoint_permission_denied(self):
        self.mock_customer_collection.find_one.return_value = {
            '_id': 'some_id',
            'clients': [{
                'client_name': 'WeatherNodeInitiative',
                'api_key': '58c8f6da-98b4-4c4b-bfa7-5b52f09ea139',
                'permissions': ['fetch-only']
            }]
        }
        response = self.app.get(f'/setup?apikey=58c8f6da-98b4-4c4b-bfa7-5b52f09ea139&username=WeatherNodeInitiative')
        self.assertEqual(response.status_code, 403)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error"], "Permission denied")

    def test_fetch_store_weather_key_with_no_permissions(self):
        self.mock_customer_collection.find_one.return_value = {
            '_id': 'some_id',
            'clients': [{
                'client_name': 'WeatherNodeInitiative',
                'api_key': '58c8f6da-98b4-4c4b-bfa7-5b52f09ea139',
                'permissions': ['fetch-only']
            }]
        }
        response = self.app.get('/fetch-store-weather?capital=paris&apikey=58c8f6da-98b4-4c4b-bfa7-5b52f09ea139')
        self.assertEqual(response.status_code, 403)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error"], "Permission denied")

if __name__ == '__main__':
    unittest.main()
