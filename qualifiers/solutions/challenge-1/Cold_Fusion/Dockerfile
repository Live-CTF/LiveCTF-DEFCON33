FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py

WORKDIR /
RUN python3 -m pip install z3-solver
RUN python3 -m pip install capstone
CMD ["python3", "solve.py"]
