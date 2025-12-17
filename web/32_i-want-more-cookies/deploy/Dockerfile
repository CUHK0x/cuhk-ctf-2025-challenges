# Use lightweight Python base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy files
COPY . /app

# Install Flask (plus any future dependencies)
RUN pip install --no-cache-dir flask

# Expose port used by Flask
EXPOSE 5000

# Run the challenge
CMD ["python", "app.py"]
