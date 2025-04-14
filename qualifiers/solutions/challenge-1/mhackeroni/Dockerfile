
FROM livectf/livectf:quals-exploit
COPY a.py /solve.py
COPY challenge /challenge
WORKDIR /
RUN python3 -m pip install --upgrade angr
CMD ["python3", "/solve.py"]