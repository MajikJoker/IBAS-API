from locust import HttpUser, task, between, TaskSet
import json

class WeatherApiTest(TaskSet):
    
    def on_start(self):
        """Called when a Locust instance starts running."""
        self.api_key = "58c8f6da-98b4-4c4b-bfa7-5b52f09ea139"
        self.api_key2 = "123"
        self.base_url = "/"
        self.username = "WeatherNodeInitiative"
    
    @task(1)
    def test_setup_endpoint(self):
        """Test the /setup endpoint."""
        response = self.client.get(f'{self.base_url}setup?apikey={self.api_key2}&username={self.username}')
        if response.status_code != 200:
            print(f"Failed to setup: {response.text}")
    
    @task(2)
    def test_fetch_store_weather(self):
        """Test the /fetch-store-weather endpoint."""
        capital = "paris"
        response = self.client.get(f'{self.base_url}fetch-store-weather?capital={capital}&apikey={self.api_key}')
        if response.status_code != 200:
            print(f"Failed to fetch and store weather: {response.text}")

    @task(2)
    def test_get_historical_data(self):
        """Test the /get-historical-data endpoint."""
        response = self.client.get(f'{self.base_url}get-historical-data?apikey={self.api_key}')
        if response.status_code != 200:
            print(f"Failed to get historical data: {response.text}")
    
    @task(1)
    def test_fetch_only(self):
        """Test the /fetch-only endpoint."""
        capital = "paris"
        response = self.client.get(f'{self.base_url}fetch-only?capital={capital}&apikey={self.api_key}')
        if response.status_code != 200:
            print(f"Failed to fetch weather data only: {response.text}")

class WebsiteUser(HttpUser):
    tasks = [WeatherApiTest]
    wait_time = between(1, 3)  # Simulate a delay between tasks