ARG UBUNTU_VERSION="22.04"
ARG SDK_VERSION="2.21.100.1"
ARG PSW_VERSION="1.18.100.1"
ARG DOMAIN="dev-c1n1.ternoa.network"
ARG PORT="8101"
ARG CODE_VERSION="0.4.4"
ARG CHAIN="alpha-net"
ARG VERSION_TAG="v0.4.4-alphanet"
ARG VERBOSITY="3"

# Support setting various labels on the final image
FROM rust:latest as builder
RUN rustup update

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ jammy main' > /etc/apt/sources.list.d/gramine.list

RUN apt-get update && apt-get upgrade && apt install -y apt-utils curl ca-certificates git build-essential wget libssl-dev git unzip pkgconf
RUN apt install -y pkg-config
RUN apt install -y gramine
RUN gramine-sgx-gen-private-key

RUN git clone https://github.com/capsule-corp-ternoa/ternoa-enclaves.git /opt/ternoa-enclaves

WORKDIR /opt/ternoa-enclaves
RUN git checkout docker
RUN cargo build --release --no-default-features --features "alpha-net"
RUN mkdir -p gramine/bin
RUN cp target/release/sgx_server gramine/bin/

WORKDIR /opt/ternoa-enclaves/gramine
RUN cd trusted && ./update-trusted.sh && cd ../
RUN make 	SGX=1 \
	SGX_DEV_BUILD=0 \
	all >> make.log 2>&1

FROM ubuntu:${UBUNTU_VERSION}
SHELL ["/bin/bash", "-c"]

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl tzdata apt-utils build-essential ca-certificates python2 \
    ocaml ocamlbuild automake autoconf libtool wget python-is-python3 git cmake \
    perl dkms linux-headers-$(uname -r) libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper \
    reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev protobuf-c-compiler libprotobuf-c-dev \
    lsb-release libsystemd0 clang llvm nettle-dev && \
    curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ jammy main' > /etc/apt/sources.list.d/gramine.list && \
    curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' > /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata libsgx-epid libsgx-quote-ex libsgx-launch libsgx-urts && \
    apt-get install -y gramine gramine-ratls-epid libprotobuf-c1

RUN apt-get install -y pkg-config

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ jammy main" \
    | tee /etc/apt/sources.list.d/gramine.list

RUN gramine-sgx-gen-private-key

WORKDIR /opt/ternoa-enclaves/gramine
COPY --from=builder /opt/ternoa-enclaves/gramine/*.manifest     \
                    /opt/ternoa-enclaves/gramine/*.manifest.sgx \
                    /opt/ternoa-enclaves/gramine/*.token        \
                    /opt/ternoa-enclaves/gramine/*.sig          \
                    /opt/ternoa-enclaves/gramine/*.args         \
                    /opt/ternoa-enclaves/gramine/bin/sgx_server \
                    ./

RUN gramine-sgx-sigstruct-view sgx_server.sig

EXPOSE $PORT
ENTRYPOINT gramine-sgx /opt/ternoa-enclaves/gramine/bin/sgx_server --domain $DOMAIN --port $PORT --verbose $VERBOSITY

LABEL version=${VERSION_TAG}
