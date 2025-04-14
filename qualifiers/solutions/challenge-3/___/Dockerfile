FROM livectf/livectf:quals-exploit

RUN apt update && apt install gdb -y
COPY solve-template.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
