
FROM livectf/livectf:quals-exploit
COPY a.py /solve.py
COPY pin /pin
COPY MyPinTool.so /MyPinTool.so
WORKDIR /
CMD ["python3", "/solve.py"]