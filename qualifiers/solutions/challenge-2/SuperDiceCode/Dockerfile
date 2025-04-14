FROM livectf/livectf:quals-exploit

COPY challenge /
COPY libc.so.6 /
COPY gaming.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
