FROM livectf/livectf:quals-exploit
RUN apt update && apt install -y gdb coreutils
RUN python3 -m pip install z3-solver
COPY solve.py /
COPY sibal.py /
WORKDIR /
CMD ["python3", "-u", "solve.py"]
