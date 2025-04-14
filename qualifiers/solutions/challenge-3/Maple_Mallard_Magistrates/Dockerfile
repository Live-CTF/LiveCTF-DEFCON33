FROM livectf/livectf:quals-exploit


#RUN pip install frida-tools

RUN apt-get update && apt-get install gdb -y

# PANIC
COPY trace.js /trace.js
COPY this.gdb /this.gdb
COPY solve-template.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
