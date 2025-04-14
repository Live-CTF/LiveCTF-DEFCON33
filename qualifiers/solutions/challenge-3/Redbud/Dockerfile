FROM livectf/livectf:quals-exploit

RUN apt update && apt install -y gdb

COPY solve.py /solve.py
COPY debug.py /debug.py

WORKDIR /
CMD ["python3", "solve.py"]
