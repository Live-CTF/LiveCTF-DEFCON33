FROM docker.io/livectf/livectf:quals-exploit

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends gdb && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt
COPY solve.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
