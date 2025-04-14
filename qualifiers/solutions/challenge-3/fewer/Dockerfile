FROM livectf/livectf:quals-exploit
WORKDIR /exp
RUN apt update && apt install -y gdb
RUN (python3 -c '__import__("os").write(1, __import__("requests").get("https://play.livectf.com/api/challenges/3/download").content)' | tar xvzf -) || true
COPY ./ ./
CMD ["python3", "exploit.py", "REMOTE"]
