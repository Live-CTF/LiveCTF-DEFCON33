FROM livectf/livectf:quals-nsjail AS base

FROM base AS build

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3 python3-networkx build-essential"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /build
WORKDIR /build
COPY generator/ generator/
WORKDIR /build/generator

# Install networkx via apt package
# RUN pip install -r requirements.txt
RUN mkdir -p samples
RUN python3 generator.py \
    --seed 344aaf028f3de0dda885173cf5cba6eb \
    --num-challenges 120 \
    --output-directory samples \
    --password-directory passwords

# RUN chmod +x samples/*

FROM base AS run

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3 build-essential"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

COPY server/ /home/livectf/
COPY --from=build /build/generator/samples /home/livectf/samples
COPY --from=build /build/generator/passwords /home/livectf/passwords
# Only put 1 reference binary and password in handout
COPY --from=build /build/generator/reference /home/livectf/reference

RUN mkdir -p /handout /handout/samples /handout/passwords
COPY config.toml nsjail.conf server/run.sh /handout/
COPY dist.Dockerfile /handout/Dockerfile
RUN cp /home/livectf/server.py /home/livectf/challenge /handout
RUN cp /home/livectf/reference/samples/challenge_0   /handout/samples
RUN cp /home/livectf/reference/passwords/challenge_0 /handout/passwords

RUN tar -czf /handout.tar.gz /handout && rm -rf /handout

COPY nsjail.conf /home/livectf/nsjail.conf
COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
