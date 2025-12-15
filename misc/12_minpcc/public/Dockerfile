FROM ubuntu@sha256:b59d21599a2b151e23eea5f6602f4af4d7d31c4e236d22bf0b62b86d2e386b8f

RUN apt-get update && apt-get install -y xinetd coreutils gcc

WORKDIR /home/ctf
RUN useradd -m ctf
COPY --chmod=555 setup.sh chall.sh start.sh /home/ctf/
COPY ./entrypoint.c /home/ctf/entrypoint.c

RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
COPY ./xinetd.conf /etc/xinetd.conf

EXPOSE 8000/tcp

WORKDIR /home/ctf
CMD ["/bin/sh", "start.sh"]
