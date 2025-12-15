FROM ubuntu:jammy-20250415.1

RUN apt-get update && apt-get install -y python3 socat

WORKDIR /home/ctfuser
COPY flag.txt /home/ctfuser/
COPY *.py /home/ctfuser/
RUN python3 -m compileall /home/ctfuser/

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"stdbuf -i0 -o0 -e0 python3 /home/ctfuser/main.py"