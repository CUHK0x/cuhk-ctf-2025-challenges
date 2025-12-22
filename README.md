# CUHK CTF 2025
hello
## Description
Below are the challenges in CUHK CTF 2025 held on 26-28 September. Writeups are redacted until the writeup workshop.

## Folder Structure Explanation
Challenge folders are placed under their corresponding categories (`crypto`, `forens`, `misc`, `pwn`, `rev`, `web`, `cloud`). Under each challenge folder, `public` folder represents the materials given to the participants. `deploy` folder contains secrets used during deployment in the challenge server. `README.md` contains challenge description and necessary challenge info. There is also a `[id]_flag.txt` for the flag used in the challenge.

## Running Challenge Server

Some challenges work with a remote server during the competition and you can run a local challenge server to mimic the situation.

⚠️ **Security Warning**

These challenge servers are intentionally vulnerable.
**Do NOT deploy them on public or production machines.**
It is strongly recommended to run them in a local environment or an isolated virtual machine.

---

### Deployment (Docker)

Each challenge that requires a server includes a `deploy/` directory containing Docker configuration files (such as `Dockerfile` and `docker-compose.yml`).

Make sure **Docker** and **Docker Compose** are installed before proceeding.

#### 1. Build and start the server

From the challenge directory:

```bash
cd deploy
docker compose up --build
```
### 2. Check container status
In a new terminal, run:
```bash
docker compose ps
```
### 3. Stop the server
To stop the running server, press `CTRL+C` in the terminal where docker compose up is running.
### 4. Shut down and remove containers
After stopping the server, clean up the containers with:
```bash
compose docker down
```
This stops and removes the challenge containers and network.
