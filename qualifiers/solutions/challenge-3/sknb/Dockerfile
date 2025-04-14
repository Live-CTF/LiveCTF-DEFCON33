FROM livectf/livectf:quals-exploit

COPY sol.py /solve.py
COPY gdbs.txt /gdbs.txt

RUN apt-get update && apt install -y gdb

WORKDIR /
CMD ["python3", "solve.py"]
