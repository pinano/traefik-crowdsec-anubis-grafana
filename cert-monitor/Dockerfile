FROM alpine:3.23

# dependencies for the check-certs.sh script
RUN apk add --no-cache jq openssl curl tzdata

# define entrypoint for a clean 'docker exec'
ENTRYPOINT ["/bin/sh", "-c"]
