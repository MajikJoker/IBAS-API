import logging
from flask import Flask
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Import routes from different modules
from ibas import ibas_routes
from verifier import verifier_routes

# Register Blueprints
app.register_blueprint(ibas_routes)
app.register_blueprint(verifier_routes)

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(debug=True, host='0.0.0.0', port=8000)
