FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py

RUN pip3 install --break-system-packages z3-solver pwntools iced-x86

WORKDIR /
CMD ["python3", "solve.py"]
