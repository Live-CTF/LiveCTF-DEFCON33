FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py
RUN pip install frida frida-tools

WORKDIR /
CMD ["python3", "solve.py"]
