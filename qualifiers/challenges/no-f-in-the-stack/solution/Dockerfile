FROM livectf/livectf:quals-exploit

ARG DEBIAN_FRONTEND=noninteractive

RUN mkdir solve
WORKDIR /solve

RUN pip install leb128 tqdm

COPY solve.py /solve

COPY entry.sh /solve

CMD ["python3", "solve.py", "--network"]
