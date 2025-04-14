FROM livectf/livectf:quals-exploit
COPY deploy /deploy
RUN apt-get update && apt-get install gdb -y

WORKDIR /
CMD ["python3", "/deploy/solve.py"]