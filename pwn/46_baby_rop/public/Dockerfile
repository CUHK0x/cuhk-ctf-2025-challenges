# ubuntu:24.04
FROM ubuntu@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8

RUN apt-get update && apt-get install -y xinetd coreutils
RUN apt-get install -y qemu-user-static

RUN useradd -m ctf
COPY ./bin/chall /home/ctf/chall
COPY ./bin/logo /home/ctf/logo
COPY ./bin/start.sh /home/ctf/start.sh
RUN chmod +x /home/ctf/start.sh

COPY ./start.sh /start.sh
RUN chmod +x /start.sh
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
COPY ./ctf.xinetd /etc/xinetd.d/ctf

RUN echo "cuhk25ctf{test}" > /flag

CMD ["/start.sh"]