
#ARG SDK_VERSION
#ENV SDK_VERSION=${SDK_VERSION:-"2.21.100.1"}

#ARG PSW_VERSION
#ENV PSW_VERSION=${PSW_VERSION:-"1.18.100.1"}

ARG UBUNTU_VERSION=22.04

# Support setting various labels on the final image
FROM rust:latest as builder

ARG ENCLAVE_CHAIN
ENV ENCLAVE_CHAIN=${ENCLAVE_CHAIN:-"mainnet"}

RUN rustup update
SHELL ["/bin/bash", "-c"]

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ jammy main' > /etc/apt/sources.list.d/gramine.list

RUN apt-get update && apt-get upgrade && apt install -y apt-utils curl ca-certificates git build-essential wget libssl-dev git unzip pkgconf
RUN apt install -y pkg-config
RUN apt install -y gramine
RUN gramine-sgx-gen-private-key

RUN git clone https://github.com/capsule-corp-ternoa/ternoa-enclaves.git /opt/ternoa-enclaves

WORKDIR /opt/ternoa-enclaves
RUN git checkout docker
RUN cd artifacts && ./get_metadata.sh && cd ../
RUN cargo build --release --no-default-features --features $ENCLAVE_CHAIN
RUN mkdir -p gramine/bin
RUN cp target/release/sgx_server gramine/bin/

WORKDIR /opt/ternoa-enclaves/gramine
RUN cd trusted && ./update-trusted.sh && cd ../
RUN make SGX=1 SGX_DEV_BUILD=0 all

# ----------------------------------------------------------------


FROM ubuntu:${UBUNTU_VERSION}
SHELL ["/bin/bash", "-c"]

ARG ENCLAVE_DOMAIN
ENV ENCLAVE_DOMAIN=${ENCLAVE_DOMAIN:-"enclave.your.domain"}

ARG ENCLAVE_PORT
ENV ENCLAVE_PORT=${ENCLAVE_PORT:-"8000"}
ARG CODE_VERSION
ENV CODE_VERSION=${CODE_VERSION:-"v0.4.5"}

ARG ENCLAVE_VERBOSITY
ENV ENCLAVE_VERBOSITY=${ENCLAVE_VERBOSITY:-3}

ENV VERSION_TAG="${CODE_VERSION}-${CHAIN}"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl tzdata apt-utils build-essential ca-certificates \
    linux-headers-$(uname -r) libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper \
    reprepro unzip pkgconf protobuf-c-compiler lsb-release libsystemd0

RUN apt-get install -y pkg-config

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ jammy main' > /etc/apt/sources.list.d/gramine.list && \
    curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' > /etc/apt/sources.list.d/intel-sgx.list

RUN apt-get update && \
    apt-get install -y --no-install-recommends tzdata libsgx-epid libsgx-quote-ex libsgx-launch libsgx-urts && \
    apt-get install -y gramine gramine-ratls-epid libprotobuf-c1

RUN gramine-sgx-gen-private-key

WORKDIR /opt/ternoa-enclaves/gramine
COPY --from=builder /opt/ternoa-enclaves/gramine ./

EXPOSE $ENCLAVE_PORT
ENTRYPOINT ["gramine-sgx", "sgx_server"]

LABEL version=$VERSION_TAG
