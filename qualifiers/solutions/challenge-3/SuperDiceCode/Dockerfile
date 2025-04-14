FROM livectf/livectf:quals-exploit

RUN apt update && apt install -y gdb

COPY solve-template.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
