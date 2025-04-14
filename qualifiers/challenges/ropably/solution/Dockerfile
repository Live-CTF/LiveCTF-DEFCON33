FROM docker.io/livectf/livectf:quals-exploit

COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt
COPY solve.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
