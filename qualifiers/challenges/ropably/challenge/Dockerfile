FROM livectf/livectf:quals-nsjail AS base

FROM base AS build

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3 build-essential"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /build
WORKDIR /build
COPY generator/ generator/
WORKDIR /build/generator
RUN mkdir -p samples
RUN python3 generator.py --seed 59f296358f5b7028593eca2edd63fb3f --num-challenges 500 --output-directory samples
RUN chmod +x samples/*

FROM base AS run

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3 build-essential"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

COPY server/ /home/livectf/
COPY --from=build /build/generator/samples /home/livectf/samples

RUN mkdir -p /handout
RUN mkdir -p /handout/samples
COPY server/run.sh config.toml nsjail.conf /handout/
COPY dist.Dockerfile /handout/Dockerfile
RUN cp /home/livectf/server.py /home/livectf/challenge /handout
RUN cp /home/livectf/samples/challenge_0 \
        /home/livectf/samples/challenge_1 \
        /home/livectf/samples/challenge_2 \
        /home/livectf/samples/challenge_3 \
        /home/livectf/samples/challenge_4 \
        /home/livectf/samples/challenge_5 \
        /home/livectf/samples/challenge_6 \
        /home/livectf/samples/challenge_7 \
        /home/livectf/samples/challenge_8 \
        /home/livectf/samples/challenge_9 \
        /home/livectf/samples/challenge_10 \
        /home/livectf/samples/challenge_11 \
        /home/livectf/samples/challenge_12 \
        /home/livectf/samples/challenge_13 \
        /home/livectf/samples/challenge_14 \
        /home/livectf/samples/challenge_15 \
        /home/livectf/samples/challenge_16 \
        /home/livectf/samples/challenge_17 \
        /home/livectf/samples/challenge_18 \
        /home/livectf/samples/challenge_19 \
        /handout/samples
RUN tar -czf /handout.tar.gz /handout && rm -rf /handout

COPY nsjail.conf /home/livectf/nsjail.conf
COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
