FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py

RUN pip3 install angr pwntools requests

WORKDIR /
CMD ["python3", "solve.py", "SILENT"]
