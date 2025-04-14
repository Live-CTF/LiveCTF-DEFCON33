FROM livectf/livectf:quals-nsjail AS base

FROM base AS build

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="build-essential"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

COPY build.sh /build.sh
COPY src/ /src/
RUN mkdir /build /handout
RUN cd / && /build.sh

COPY dist.Dockerfile /handout/Dockerfile
COPY config.toml nsjail.conf /handout/
RUN tar -czf /handout.tar.gz /handout

FROM base AS run

ARG REQUIRED_PACKAGES="python3 python3-pip"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*
RUN rm -rf /usr/lib/python*/EXTERNALLY-MANAGED

COPY src/requirements.txt /home/livectf/
RUN pip install -r /home/livectf/requirements.txt
COPY src/sentiment.py /home/livectf/
WORKDIR /home/livectf
RUN python3 -c 'import sentiment'

COPY --from=build /build/challenge /home/livectf/
COPY --from=build /handout.tar.gz /handout.tar.gz
COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
