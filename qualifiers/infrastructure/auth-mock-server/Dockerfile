FROM docker.io/python:slim-buster

RUN mkdir -p /app
COPY requirements.txt /app/
RUN pip install -r /app/requirements.txt
COPY server.py validate-ticket /app/

WORKDIR /app
CMD ["python3", "server.py"]
