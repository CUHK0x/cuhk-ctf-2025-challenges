#!/bin/bash
set -e

# Initialize database if missing
if [ ! -f "your_db_file.db" ]; then
    python init_db.py
fi

# Start Flask app with Gunicorn
exec gunicorn -w 4 -b 0.0.0.0:8080 app:app