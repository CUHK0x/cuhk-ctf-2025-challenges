## Deployment

```bash
cd deploy/
docker build -t cookie-monster .
docker run -d -p 5000:5000 cookie-monster
