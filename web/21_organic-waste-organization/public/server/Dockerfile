FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -m a=rwx uploads

USER nobody
ENV PORT=5000
CMD ["/bin/sh", "run_server.sh"]
