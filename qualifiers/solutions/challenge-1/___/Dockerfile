# FROM python:3-slim AS base
FROM livectf/livectf:quals-exploit AS base


RUN pip3 install capstone z3-solver

COPY exploit.py .

CMD ["python3", "exploit.py"]
