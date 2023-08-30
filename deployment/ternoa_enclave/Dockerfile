# Support setting various labels on the final image
FROM ubuntu:22.04
SHELL ["/bin/bash", "-c"]

RUN cd /opt

RUN apt update && apt install -y \
    curl ca-certificates git build-essential python2 ocaml ocamlbuild \
    automake autoconf libtool wget python-is-python3 libssl-dev git cmake \
    perl dkms linux-headers-$(uname -r) libcurl4-openssl-dev \
    protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf \
    libboost-dev libboost-system-dev libboost-thread-dev protobuf-c-compiler \
    libprotobuf-c-dev lsb-release libsystemd0 jq clang llvm nettle-dev

RUN apt install -y pkg-config

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    source "$HOME/.cargo/env" && \
    rustup update

RUN apt install python3-pip -y && \
    pip install --upgrade pip && \
    pip install "scalecodec>=1.1.2" && \
    pip install substrate-interface && \
    pip install base58

ENV SDK_VERSION="2.21.100.1"
ENV PSW_VERSION="1.18.100.1"
ARG VERSION="0.4.3"
ENV DOMAIN="dev-c1n1.ternoa.network"
ENV PORT="8100"
ARG VERSION_TAG="phase-5"
ENV CHAIN="main-net release-build"

WORKDIR /opt/linug-sgx

RUN SDK_VERSION="2.21.100.1" && PSW_VERSION="1.18.100.1" && \
    git clone https://github.com/intel/linux-sgx.git /opt/linux-sgx && \
    cd /opt/linux-sgx && \
    make preparation && \
    cp external/toolset/ubuntu20.04/* /usr/local/bin && \
    make clean && \
    make sdk_install_pkg && \
    chmod +x /opt/linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_$SDK_VERSION.bin && \
    cp /opt/linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_$SDK_VERSION.bin /opt/ && \
    /opt/sgx_linux_x64_sdk_$SDK_VERSION.bin --prefix /opt && \
    source /opt/sgxsdk/environment && \
    cd /opt/linux-sgx && \
    mkdir /etc/init && \
    touch /etc/aesmd.conf && \
    make clean && \
    mkdir /opt/psw && \
    make deb_psw_pkg && \
    cp $(find . -name "*.deb") /opt/psw && \
    sudo dpkg -i /opt/psw/libsgx-headers_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-quote-ex_$SDK_VERSION-jammy1_amd64.deb  && \
    sudo dpkg -i /opt/psw/libsgx-quote-ex-dev_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-enclave-common_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-enclave-common-dev_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-urts_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-ae-pce_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-pce-logic_$PSW_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-epid_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-epid-dev_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-launch_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-launch-dev_$SDK_VERSION-jammy1_amd64.deb && \ 
    sudo dpkg -i /opt/psw/sgx-aesm-service_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-ae-epid_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-aesm-pce-plugin_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-aesm-epid-plugin_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-uae-service_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-ae-le_$SDK_VERSION-jammy1_amd64.deb && \
    sudo dpkg -i /opt/psw/libsgx-aesm-launch-plugin_$SDK_VERSION-jammy1_amd64.deb

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
    | tee /etc/apt/sources.list.d/gramine.list

RUN apt update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata && apt-get install -y gramine

RUN is-sgx-available && \
    gramine-sgx-gen-private-key
#    cp -r ~/.config /root/

WORKDIR /ternoa_enclave
ADD . /ternoa_enclave/
RUN CHAIN="main-net release-build" /opt/ternoa_enclave/scripts/start-server.sh --domain $DOMAIN --port $PORT

EXPOSE 8100/tcp
ENTRYPOINT ["CHAIN='main-net release-build' /opt/ternoa_enclave/scripts/start-server.sh", "--domain $DOMAIN --port 8100"]

LABEL version="$VERSION"
