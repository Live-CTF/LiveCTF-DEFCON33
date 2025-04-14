FROM livectf/livectf:quals-exploit

RUN apt-get update && \
    apt-get install -y python3-pip python3-dev build-essential && \
    pip3 install angr
    
COPY solve.py /
WORKDIR /

CMD ["python3", "solve.py"]
