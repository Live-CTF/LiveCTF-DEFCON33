FROM livectf/livectf:quals-exploit

COPY sol.py /solve.py

RUN pip install z3-solver

WORKDIR /
CMD ["python3", "solve.py"]
