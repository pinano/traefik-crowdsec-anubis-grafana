FROM python:3.11-alpine

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.0 PyYAML==6.0.1 tldextract==5.1.0 gunicorn==21.2.0 gevent==23.9.1 Flask-Limiter==3.5.0 Flask-WTF==1.2.1

COPY . .

# We will need docker to restart the stack, but actually we will call the host script
# So we might need docker client or just exec into the host via socket if possible
# To keep it simple, we assume the script can be run if we mount the socket and have docker cli
RUN apk add --no-cache docker-cli docker-compose bash ncurses openssl

EXPOSE 5000

CMD ["gunicorn", "--config", "gunicorn_config.py", "app:app"]
