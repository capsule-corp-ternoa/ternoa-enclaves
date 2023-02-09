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
https://gramine.readthedocs.io/en/stable/quickstart.html

check sgx availability : 
```bash
is-sgx-available
```

### ● Install Intel-SGX SDK/PSW
depending on kernel version you may need to install [intel-sgx-driver](https://github.com/intel/linux-sgx-driver).

SDK installation [Doc](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)

SDK code [Repository](https://github.com/intel/linux-sgx)


### ● Generate Certificates
Valid certtificates specific for your machine (URI or IP) should be generated using scripts and config file in ```credentials/certificates/``` folder. 
- TODO : generate certificates in enclave

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
scripts/start-server.sh -b -p 8101 -i DEV0-C1N1EI
```
otherwise you need to run in simulation mode : 
```shell
make start-gramine-server
```
default port is 8100 .

To stop the Enclave properly :
```shell
scripts/stop-server.sh -p 8101
```
## Quote and Report
If enclave starts successfully, the quote data, IAS reports and log information will be available on [quote](./quote/) folder.
All of these data will be removes by stop-server.sh command.

## Client
An importable Postman [json file](./client/postman.json) is available at client folder. CA Certificate file for the machine should be introduced to Postman.
Sample ```curl``` commands are provided on [client.sh](./client/client.sh) file.

