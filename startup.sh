#!/bin/bash
# Activate the virtual environment
source antenv/bin/activate
# Start the Flask application
exec gunicorn --bind 0.0.0.0:8000 IBAS:app
