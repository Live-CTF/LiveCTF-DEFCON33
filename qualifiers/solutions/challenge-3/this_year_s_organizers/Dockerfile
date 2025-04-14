FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py
RUN apt update && apt install -y gdb

WORKDIR /
CMD ["python3", "solve.py"]
