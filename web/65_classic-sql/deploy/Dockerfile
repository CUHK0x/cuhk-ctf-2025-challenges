FROM python:3.12

WORKDIR /app

# Copy only requirements (or just install packages) first
# Install Flask and Gunicorn
RUN pip install --no-cache-dir flask gunicorn


# Now copy the source code
COPY . /app

# Give nobody ownership of /app so it can write DB
RUN chown -R nobody:nogroup /app

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

#create a non-root user & switch to it

USER nobody

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]