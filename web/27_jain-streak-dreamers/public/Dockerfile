FROM ocaml/opam:alpine-ocaml-5.1

# Install system dependencies
RUN sudo apk add --update libev-dev openssl-dev gmp-dev libffi-dev sqlite-dev argon2-dev  

WORKDIR /home/opam

# Install dependencies
ADD app.opam .
RUN opam install . --deps-only -y

# Seed database
ADD init.sql .
RUN sqlite3 db.sqlite < init.sql

# Build the project
ADD . .
RUN sudo chown -R opam secret
RUN mv secret/flag2.txt secret/$(cat secret/flag2.txt)
RUN opam exec -- dune build

# Start server
WORKDIR /home/opam/_build/default
CMD ./server/app.exe
