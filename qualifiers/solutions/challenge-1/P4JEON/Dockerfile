FROM livectf/livectf:quals-exploit

ARG REQUIRED_PACKAGES="python3 python3-pip"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

# pip 설치 패키지 (z3-solver, capstone)
RUN pip3 install --break-system-packages z3-solver capstone pwntools

COPY solve.py /
WORKDIR /
CMD ["python3", "solve.py"]

