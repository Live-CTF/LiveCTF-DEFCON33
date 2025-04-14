FROM livectf/livectf:quals-exploit

RUN python3 -m pip install angr pwntools

COPY solve.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
