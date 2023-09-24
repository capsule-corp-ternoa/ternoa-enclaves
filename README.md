# Ternoa TEE server for Secret-NFT

## Prerequisites

All the following installation steps for Ubuntu 22.04 are automated in an [Install Script](./install.sh) .

### ● Install build-tools

ubuntu :  

```bash
sudo apt install clang llvm pkg-config nettle-dev libssl-dev openssl dkms
```

### ● Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### ● Install Gramine

<https://gramine.readthedocs.io/en/stable/quickstart.html>

check sgx availability :

```bash
is-sgx-available
```

### ● Install Intel-SGX SDK/PSW

depending on kernel version you may need to install [intel-sgx-driver](https://github.com/intel/linux-sgx-driver).

SDK installation [Doc](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)

SDK code [Repository](https://github.com/intel/linux-sgx)

### ● Fetch Metadata

When metadata of the chain is updated, Go to ```./artifacts``` folder and run :

```bash
./gen_metadata.sh
```

this will fetch latest metadata of Ternoa chains.

Sometimes it is useful to have a json version of metadata :

```bash
subxt codegen --url wss://alphanet.ternoa.com:443 > ternoa_alphanet.code
```

## Start an Enclave

Make sure you are on a SGX machine, driver and sdk are installed.
You have to specify the chain which you want to use.

This command will build a binary for dev-0 chain :

Make sure you are on a SGX machine, driver and sdk are installed.
You have to specify the chain which you want to use.

This command will build a binary for dev-0 chain :

```shell
sudo CHAIN="dev0" ./scripts/start-server.sh --domain dev-c1n1.ternoa.network --port 8100  --build --verbose 2
```

To use official binary in github :

```shell
sudo CHAIN="mainnet" ./scripts/start-server.sh --domain mainnet-c1n1.ternoa.network --port 8100  --fetch --verbose 2
```

### Start Parameters

 CHAIN         environment variable that specifies for which endpoint the binary should be built, it also specifies the signing key

 --build       Builds the source code and signs the binary everytime

 --fetch       Downloads binary and signature from Ternoa github repository

 --domain      Domain of SGX machine

 --port        Different enclaves on the same machine need to have different ports

## Resume an Enclave

It is similar to Start, but it won't compile the binary :

```shell
sudo CHAIN="alphanet" ./scripts/resume-server.sh --domain alphanet-c1n1.ternoa.network --port 8100 --build --verbose 2
```

## Stop an Enclave

To stop the Enclave properly :

```shell
sudo scripts/stop-server.sh --port 8100
```

## Clear an Enclave

To clear the Enclave and remove all intermediate sgx files and binaries :

```shell
sudo scripts/clear-server.sh
```

## Docker

To create a new image:

```shell
docker build --rm --no-cache \
    -t ternoa-sgx:v0.4.4-alphanet \
    -t ternoa-sgx:latest \
    --build-arg UBUNTU_VERSION=22.04 \
    --build-arg ENCLAVE_CHAIN=alphanet \
    --build-arg ENCLAVE_DOMAIN=enclave.domain.me \
    --build-arg ENCLAVE_PORT=8000 \
    --build-arg ENCLAVE_VERBOSITY=3 \
    .
```

To start a container:

```shell
ENCLAVE_VERSION=v0.4.4-dev0net \
ENCLAVE_DNS=xxx.xxx.xxx.xxx \
ENCLAVE_DOMAIN=enclave.newdomain.me \
ENCLAVE_PORT=9000 \
ENCLAVE_VERBOSITY=3 \
docker-compose up

```

## Client

An importable Postman [json file](./client/postman.json) is available at client folder. CA Certificate file for the machine should be introduced to Postman.
Sample ```curl``` commands are provided on [client.sh](./client/client.sh) file.

## Signing Tool

A simple tool provide correct request format to enclave API endpoints
[Readme](./tools/README.md)
