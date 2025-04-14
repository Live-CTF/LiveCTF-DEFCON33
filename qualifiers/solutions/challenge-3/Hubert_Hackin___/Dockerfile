FROM livectf/livectf:quals-exploit

RUN apt update
RUN apt install -y gdb

COPY solve.py /solve.py
COPY worker.py /worker.py

WORKDIR /
CMD ["python3", "solve.py"]
