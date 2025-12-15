FROM python:3.13-alpine

RUN apk --no-cache add socat
RUN adduser -D yakitori
RUN python3 -m pip install pycryptodome

WORKDIR /app
COPY --chown=root favourite-message.py /app
COPY --chown=root flag.txt /app
RUN chmod -R 555 /app

USER yakitori
EXPOSE 3000

CMD ["socat", "TCP-LISTEN:3000,fork,reuseaddr", "EXEC:python3 -u favourite-message.py,pty,stderr,echo=0"]