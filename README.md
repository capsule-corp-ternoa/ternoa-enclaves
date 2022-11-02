# Ternoa TEE server for Secret-NFT

## Prerequisites

### ● Install build-tools

ubuntu :  
```bash
sudo apt install clang llvm pkg-config nettle-dev libssl-dev openssl
```

### ● Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### ● Install Gramine
https://gramine.readthedocs.io/en/stable/quickstart.html

check sgx availability : 
```bash
is-gramine-available
```

### ● Install Intel-SGX SDK

use wget to download proper file : 
https://download.01.org/intel-sgx/latest/linux-latest/distro/

[Doc](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)
[Repository](https://github.com/intel/linux-sgx)

### ● Generate Certificates
Self-signed certificates are not supported, you must provide valid certtificates specific for your machine (URI or IP) and put them of ```credentials/certificates/ssl_certificates``` folder. 

### ● Fetch Metadata
When metadata of the chain is updated, use ```subxt``` command-line to get new metadata from chain rpc endpoint:

```bash
subxt metadata --url wss://alphanet.ternoa.com:443 > ternoa_alphanet.scale
```
then put the file in ```credentials/artifacts``` folder.

Sometimes it is useful to have a json version of metadata : 
```bash
subxt codegen --url wss://alphanet.ternoa.com:443 > ternoa_alphanet.code
```

## Build and Run
If you are on a SGX machine :

```shell
make SGX=1 start-gramine-server
```
otherwise you need to run in simulation mode : 
```shell
make start-gramine-server
```
default port is 3000 .

## Client
Sample ```curl``` commands are provided on [client.sh](./client.sh) file. 
