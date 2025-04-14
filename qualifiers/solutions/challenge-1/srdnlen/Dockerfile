FROM livectf/livectf:quals-exploit

COPY solve.py /

WORKDIR /

COPY requirements.txt .

RUN pip3 install -r requirements.txt

CMD ["python3", "solve.py"]