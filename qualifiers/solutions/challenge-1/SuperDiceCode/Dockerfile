FROM livectf/livectf:quals-exploit

RUN pip install claripy angr pwntools

COPY solve.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
