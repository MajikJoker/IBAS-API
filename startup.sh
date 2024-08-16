#!/bin/bash
gunicorn --bind=0.0.0.0:8000 IBAS:app --log-level=info --access-logfile=-
