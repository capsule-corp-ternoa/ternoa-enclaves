# Ternoa TEE server for Secret-NFT

## Prerequisites

### ● Install Gramine
https://gramine.readthedocs.io/en/stable/quickstart.html

### ● Certificates
Self-signed certificates are not supported, you must provide valid certtificates specific for your machine (URI or IP) and put them of ```credentials/certificates/ssl_certificates``` folder. 

### ● Metadata
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
