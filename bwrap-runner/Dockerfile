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
        git \
        curl \
        build-essential \
        pkg-config \
        python3 \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-venv \
        python3-wheel \
    && python3 -m pip install --break-system-packages --no-cache-dir --upgrade pip \
    && rm -rf /var/lib/apt/lists/*

# Install the reusable local sandbox runner under a stable image path so research
# provider agents (which use this image as their container base) can invoke the
# runner from inside their own container without depending on a separate Ploinky
# runner agent or MCP hop.
COPY bin/ /opt/bwrap-runner/bin/
COPY lib/ /opt/bwrap-runner/lib/
RUN chmod +x /opt/bwrap-runner/bin/sandbox-exec.mjs \
    && chmod +x /opt/bwrap-runner/bin/healthcheck.mjs \
    && printf '#!/bin/sh\nexec /usr/local/bin/node /opt/bwrap-runner/bin/sandbox-exec.mjs "$@"\n' \
        > /usr/local/bin/bwrap-sandbox-exec \
    && chmod +x /usr/local/bin/bwrap-sandbox-exec

WORKDIR /code
