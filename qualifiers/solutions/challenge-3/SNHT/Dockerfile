FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py

# install valgrind
RUN apt-get update && \
apt-get install -y valgrind


WORKDIR /
CMD ["python3", "solve.py"]
