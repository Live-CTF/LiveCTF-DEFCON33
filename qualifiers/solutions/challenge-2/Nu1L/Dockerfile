FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py

RUN pip3 install leb128
WORKDIR /
CMD ["python3", "solve.py"]
