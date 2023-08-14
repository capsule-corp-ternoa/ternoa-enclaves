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

When metadata of the chain is updated, Go to ```credentials/artifacts``` folder and run :

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

```shell
sudo CHAIN="dev-0" ./scripts/start-server.sh --domain dev-c1n1.ternoa.network --port 8102  --dev
```

For official binary which uses mainnet chain, you need this command :
This command will build a binary for mainnet chain :

```shell
sudo CHAIN="mainnet" ./scripts/start-server.sh --domain mainnet-c1n1.ternoa.network --port 8100  --release
```

### Start Parameters

 CHAIN         environment variable that specifies for which wss endpoint the binary should be built

 --dev         builds and signs the binary everytime, so you need to provide password for signing with cosign private-key.

 --release     downloads binary and signature from Ternoa github
 repository

 --domain      is critical for certificates of tls/https

 --port        different enclaves on the same machine need to have
 different ports

## Resume an Enclave

It is similar to Start, but it won't compile the binary :

```shell
sudo CHAIN="alphanet" ./scripts/resume-server.sh --domain alphanet-c1n1.ternoa.network --port 8101 --dev
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

## Client

An importable Postman [json file](./client/postman.json) is available at client folder. CA Certificate file for the machine should be introduced to Postman.
Sample ```curl``` commands are provided on [client.sh](./client/client.sh) file.

## Signing Tool

[Readme](./toolds/README.md)
