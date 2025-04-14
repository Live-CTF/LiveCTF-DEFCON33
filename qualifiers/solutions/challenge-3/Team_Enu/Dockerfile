FROM livectf/livectf:quals-exploit

RUN apt-get update
RUN apt-get -y install gdb

COPY solve-template.py /solve.py
COPY gdb-script.py /gdb-script.py

WORKDIR /
CMD ["python3", "solve.py"]
