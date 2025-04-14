FROM livectf/livectf:quals-exploit

RUN pip3 install z3-solver

COPY binarystream.py /binarystream.py
COPY solve_real.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
