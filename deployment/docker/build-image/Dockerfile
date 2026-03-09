ARG UBUNTU_VERSION=22.04

# ---------- Stage 1: Build the Rust binary ----------
FROM rust:1.79 AS ternoa-rust

ARG ENCLAVE_CHAIN
ENV ENCLAVE_CHAIN=${ENCLAVE_CHAIN:-"mainnet"}

RUN rustup update
SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get install -y apt-utils curl ca-certificates git build-essential wget libssl-dev unzip pkgconf pkg-config

RUN git clone https://github.com/capsule-corp-ternoa/ternoa-enclaves.git /opt/ternoa-enclaves

WORKDIR /opt/ternoa-enclaves
RUN git checkout v0.5.3-rc1

WORKDIR /opt/ternoa-enclaves/artifacts
RUN cargo install --version 0.36.0 subxt-cli --locked
RUN ./get_metadata.sh

WORKDIR /opt/ternoa-enclaves
RUN cargo build --release --no-default-features --features $ENCLAVE_CHAIN

# ---------- Stage 2: Minimal runtime image ----------
FROM ubuntu:${UBUNTU_VERSION} AS ternoa-runtime
SHELL ["/bin/bash", "-c"]

ARG CODE_VERSION
ENV CODE_VERSION=${CODE_VERSION:-"v0.5.3-rc1"}

ARG ENCLAVE_CHAIN
ENV ENCLAVE_CHAIN=${ENCLAVE_CHAIN:-"mainnet"}

ARG ENCLAVE_VERBOSITY
ENV ENCLAVE_VERBOSITY=${ENCLAVE_VERBOSITY:-3}
ENV VERSION_TAG="${CODE_VERSION}-${ENCLAVE_CHAIN}"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl tzdata ca-certificates libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ternoa-enclaves
COPY --from=ternoa-rust /opt/ternoa-enclaves/target/release/sgx_server ./sgx_server

EXPOSE 443
ENTRYPOINT ["./sgx_server"]

LABEL version=$VERSION_TAG
