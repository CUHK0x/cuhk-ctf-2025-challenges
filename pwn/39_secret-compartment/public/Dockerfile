FROM ubuntu:25.10

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \ 
	apt-get install -y socat && \
	rm -rf /var/lib/apt/lists/*
RUN useradd -M yakitori

WORKDIR /app
COPY --chown=root service ./service
COPY --chown=root flag.txt ./compartment.txt
RUN chmod 755 /app && chmod 755 service && chmod 644 compartment.txt

CMD ["socat", "TCP-LISTEN:3000,fork,reuseaddr", "EXEC:./service,su=yakitori,stderr"]
EXPOSE 3000