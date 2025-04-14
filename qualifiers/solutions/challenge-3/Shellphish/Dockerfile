FROM livectf/livectf:quals-exploit

RUN pip install nclib angr unicorn==2.0.1.post1
COPY solve-template.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
