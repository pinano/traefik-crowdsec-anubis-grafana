FROM alpine:3.23

# dependencies for check scripts: certs (jq, openssl), dns (bind-tools), crowdsec (docker-cli)
RUN apk add --no-cache jq openssl curl tzdata coreutils bind-tools docker-cli

# define entrypoint for a clean 'docker exec'
ENTRYPOINT ["/bin/sh", "-c"]