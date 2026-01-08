FROM python:3.11-alpine

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY . .

# We will need docker to restart the stack, but actually we will call the host script
# So we might need docker client or just exec into the host via socket if possible
# To keep it simple, we assume the script can be run if we mount the socket and have docker cli
RUN apk add --no-cache docker-cli bash ncurses

EXPOSE 5000

CMD ["python", "app.py"]
