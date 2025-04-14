FROM livectf/livectf:quals-exploit

RUN pip install triton-library==1.0.0rc4
COPY solve-template.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
