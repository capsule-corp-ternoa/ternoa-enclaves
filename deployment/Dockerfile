ARG UBUNTU_VERSION="22.04"
ARG SDK_VERSION="2.21.100.1"
ARG PSW_VERSION="1.18.100.1"
ARG CODE_VERSION="0.4.4"
ARG DOMAIN="dev-c1n1.ternoa.network"
ARG PORT="8100"
ARG VERSION_TAG="v0.4.4-mannet"
ARG CHAIN="main-net"

# Support setting various labels on the final image
FROM rust:latest as builder
RUN rustup update

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ focal main' > /etc/apt/sources.list.d/gramine.list

RUN apt update && apt upgrade && apt install -y apt-utils curl ca-certificates git build-essential wget libssl-dev git  unzip pkgconf
RUN apt install -y pkg-config
RUN apt-get install -y gramine
RUN gramine-sgx-gen-private-key

RUN git clone https://github.com/capsule-corp-ternoa/ternoa-enclaves.git /opt/ternoa-enclaves

WORKDIR /opt/ternoa-enclaves
RUN git checkout docker
RUN cargo build --release --no-default-features --features ${CHAIN}
RUN cp target/release/sgx_server gramine/bin/
RUN cd gramine/trusted/ && ./update-trusted.sh


FROM ubuntu:${UBUNTU_VERSION}
SHELL ["/bin/bash", "-c"]

RUN apt update && apt install -y apt-utils curl ca-certificates git build-essential wget libssl-dev git  unzip pkgconf
RUN apt install -y pkg-config


RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
    | tee /etc/apt/sources.list.d/gramine.list

RUN apt update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata && apt-get install -y gramine

RUN is-sgx-available && \
    gramine-sgx-gen-private-key

RUN git clone https://github.com/capsule-corp-ternoa/ternoa-enclaves.git /opt/ternoa-enclaves
WORKDIR /opt/ternoa-enclaves
RUN ./scripts/build-sign.sh "main-net"
RUN 

EXPOSE ${PORT}/tcp
ENTRYPOINT CHAIN=${CHAIN} /opt/ternoa_enclave/scripts/start-server.sh --domain ${DOMAIN} --port ${PORT}

LABEL version=${CODE_VERSION}
