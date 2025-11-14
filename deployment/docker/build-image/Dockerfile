
ARG UBUNTU_VERSION=22.04
ARG GRAMINE_VERSION=1.8
ARG GRAMINE_RATLS_EPID_VERSION=1.8
ARG GRAMINE_PACKAGE_BASE_URL=https://packages.gramineproject.io/pool/main/g/gramine

# compiler version is fixed for mrenclave
FROM rust:1.79 as ternoa-rust

ARG GRAMINE_VERSION
ARG GRAMINE_PACKAGE_BASE_URL

ARG ENCLAVE_CHAIN
ENV ENCLAVE_CHAIN=${ENCLAVE_CHAIN:-"mainnet"}

RUN rustup update
SHELL ["/bin/bash", "-c"]

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ 1.8 main' > /etc/apt/sources.list.d/gramine.list

RUN apt-get update && apt-get install -y apt-utils curl ca-certificates git build-essential wget libssl-dev git unzip pkgconf
RUN apt-get install -y pkg-config
RUN curl -fsSLo /tmp/gramine_${GRAMINE_VERSION}_amd64.deb ${GRAMINE_PACKAGE_BASE_URL}/gramine_${GRAMINE_VERSION}_amd64.deb && \
    apt install -y /tmp/gramine_${GRAMINE_VERSION}_amd64.deb && \
    rm -f /tmp/gramine_${GRAMINE_VERSION}_amd64.deb
RUN gramine-sgx-gen-private-key

RUN git clone https://github.com/capsule-corp-ternoa/ternoa-enclaves.git /opt/ternoa-enclaves

WORKDIR /opt/ternoa-enclaves
#RUN git checkout master
RUN git checkout v0.5.2

WORKDIR /opt/ternoa-enclaves/artifacts
RUN cargo install --version 0.36.0 subxt-cli --locked
RUN ./get_metadata.sh
RUN ls -lts

WORKDIR /opt/ternoa-enclaves
RUN cargo build --release --no-default-features --features $ENCLAVE_CHAIN
RUN mkdir -p gramine/bin
RUN cp target/release/sgx_server gramine/bin/

WORKDIR /opt/ternoa-enclaves/gramine
RUN cd trusted && ./update-trusted.sh && cd ../
RUN make SGX=1 SGX_DEV_BUILD=0 all

# ----------------------------------------------------------------


FROM ubuntu:${UBUNTU_VERSION} as ternoa-gramine

ARG GRAMINE_VERSION
ARG GRAMINE_RATLS_EPID_VERSION
ARG GRAMINE_PACKAGE_BASE_URL
SHELL ["/bin/bash", "-c"]

ARG CODE_VERSION
ENV CODE_VERSION=${CODE_VERSION:-"v0.5.2"}

ARG ENCLAVE_VERBOSITY
ENV ENCLAVE_VERBOSITY=${ENCLAVE_VERBOSITY:-3}
ENV VERSION_TAG="${CODE_VERSION}-${CHAIN}"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl tzdata apt-utils ca-certificates libssl-dev reprepro lsb-release

    RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ 1.8 main' > /etc/apt/sources.list.d/gramine.list && \
    curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' > /etc/apt/sources.list.d/intel-sgx.list

RUN apt-get update && \
    apt-get install -y --no-install-recommends tzdata libsgx-epid libsgx-quote-ex libsgx-launch libsgx-urts libprotobuf-c1 && \
    curl -fsSLo /tmp/gramine_${GRAMINE_VERSION}_amd64.deb ${GRAMINE_PACKAGE_BASE_URL}/gramine_${GRAMINE_VERSION}_amd64.deb && \
    curl -fsSLo /tmp/gramine-ratls-epid_${GRAMINE_RATLS_EPID_VERSION}_amd64.deb ${GRAMINE_PACKAGE_BASE_URL}/gramine-ratls-epid_${GRAMINE_RATLS_EPID_VERSION}_amd64.deb && \
    apt install -y /tmp/gramine_${GRAMINE_VERSION}_amd64.deb /tmp/gramine-ratls-epid_${GRAMINE_RATLS_EPID_VERSION}_amd64.deb && \
    rm -f /tmp/gramine_${GRAMINE_VERSION}_amd64.deb /tmp/gramine-ratls-epid_${GRAMINE_RATLS_EPID_VERSION}_amd64.deb

RUN gramine-sgx-gen-private-key

WORKDIR /opt/ternoa-enclaves/gramine
COPY --from=ternoa-rust /opt/ternoa-enclaves/gramine ./

EXPOSE 443
ENTRYPOINT ["gramine-sgx", "sgx_server"]

LABEL version=$VERSION_TAG
