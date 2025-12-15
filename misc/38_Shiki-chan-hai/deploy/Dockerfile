# Use an official Python base image
FROM python:3.11-slim

# Install socat
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Add challenge files
COPY AiScReam.py .
COPY cookie_and_cream.txt .
# Executable permissions are set in git instead
COPY run.sh .

# Create User
RUN useradd -m ctfuser

# uncomment the following line of command when testing the docker image on Windows OS
# RUN sed -i 's/\r$//' /app/run.sh

# Run socat to expose the challenge. Run the server as root, but switch to a different user for
# the subprocess.
CMD ["/usr/bin/socat", "-d2", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:\"/app/run.sh\",su=ctfuser"]