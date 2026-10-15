# The acceptance check records the resolved image ID alongside its result.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    adduser apt-utils ca-certificates gnupg python3 \
    && rm -rf /var/lib/apt/lists/*
