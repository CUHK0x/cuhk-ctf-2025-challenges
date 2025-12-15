FROM python:3.13-alpine

RUN apk --no-cache add socat
RUN adduser -D yakitori
RUN python3 -m pip install pycryptodome

WORKDIR /app
COPY --chown=root chal.py /app
COPY --chown=root SquigglyStuff.py /app
COPY --chown=root flag.txt /app
RUN chmod -R 555 /app

USER yakitori
EXPOSE 3000

CMD ["socat", "TCP-LISTEN:3000,fork,reuseaddr", "EXEC:timeout 30 python3 -u chal.py,pty,stderr,echo=0"]