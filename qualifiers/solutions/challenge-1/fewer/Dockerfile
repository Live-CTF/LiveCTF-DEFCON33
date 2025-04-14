FROM livectf/livectf:quals-exploit

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y python3-pip
RUN pip install angr

COPY solve-template.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
