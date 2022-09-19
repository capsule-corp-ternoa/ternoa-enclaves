# Ternoa TEE server for Secret-NFT

## Prerequisites

### Install gramine
https://gramine.readthedocs.io/en/stable/quickstart.html

### Certificates
Self-signed certificates are not supported, you must provide valid certtificates specific for your machine (URI or IP) and put them of ```credentials/certificates/ssl_certificates``` folder. 

## Build
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
Sample ```curl``` commands are provided on client.sh file. 
