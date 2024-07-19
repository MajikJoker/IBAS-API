#!/bin/bash
# Activate the virtual environment
source antenv/bin/activate
# Start the Flask application
exec gunicorn --bind 0.0.0.0:8000 --workers 3 --timeout 120 --graceful-timeout 120 --log-level debug --access-logfile '-' --error-logfile '-' IBAS:app
