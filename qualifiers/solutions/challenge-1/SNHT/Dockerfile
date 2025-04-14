FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py

# install angr
RUN apt-get update && \
    apt-get install -y python3-pip && \
    pip3 install angr

WORKDIR /
CMD ["python3", "solve.py"]
