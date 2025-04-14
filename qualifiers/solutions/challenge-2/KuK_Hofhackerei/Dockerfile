FROM livectf/livectf:quals-exploit

RUN pip install leb128

COPY . .
COPY solve-template.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
