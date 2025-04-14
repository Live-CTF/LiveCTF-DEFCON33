FROM livectf/livectf:quals-nsjail

ARG REQUIRED_PACKAGES="python3 python3-pip"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

RUN rm -rf /usr/lib/python*/EXTERNALLY-MANAGED
COPY requirements.txt challenge nsjail.conf sentiment.py /home/livectf/
RUN pip install -r /home/livectf/requirements.txt
WORKDIR /home/livectf
RUN python3 -c 'import sentiment'

COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
