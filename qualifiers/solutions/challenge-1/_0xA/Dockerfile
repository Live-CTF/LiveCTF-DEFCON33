FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py

RUN pip install angr

WORKDIR /
CMD ["python3", "solve.py"]
