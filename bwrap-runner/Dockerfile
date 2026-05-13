FROM node:24.15.0-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
        ca-certificates \
        bash \
        coreutils \
        findutils \
        grep \
        sed \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code
