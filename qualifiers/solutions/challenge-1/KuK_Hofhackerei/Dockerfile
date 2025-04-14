FROM livectf/livectf:quals-exploit
RUN pip install angr
COPY sploit.py /
WORKDIR /
CMD ["python3", "sploit.py"]
