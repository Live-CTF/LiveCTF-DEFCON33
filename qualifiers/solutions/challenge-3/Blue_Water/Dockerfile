FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py
COPY gdb-trace.py /gdb-trace.py

RUN apt update && apt install -y gdb python3

WORKDIR /
CMD ["python3", "solve.py"]
