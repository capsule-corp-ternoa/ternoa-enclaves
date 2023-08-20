A tool to generate signed json body to be used for in Postman/cUrl requests to Ternoa sgx enclave API endpoints.


## Build
Compile the binary for your desired chain, i.e dev-0, alpha-net, main-net

default feature is alpha-net.

``` shell
cargo build --release --no-default-features --features main-net
``` 

## Run

Options:

  -s, --seed SEED-PHRASE &emsp;&emsp; Seed Phrase for Admin or NFT-Owner 

  -a, --api-version API_VERSION  &emsp;&emsp;  Version of backup API i.e 0.2.0 , 0.3.0

  -f, --file FILE-PATH  &emsp;&emsp;  Path to (ZIP-) File, containing sealed NFT key-shares backups

  -n, --nftid NFTID  &emsp;&emsp;  NFT-ID for storing keyshares in enclave

 
* Generate request for bulk backup
  
``` shell
sgx_signer --seed "12 words seed of a whitelisted admin"
```

* Generate request for older version bulk backup
  
``` shell
sgx_signer --seed "12 words seed of a whitelisted admin" --api-version 0.2.0 
```

* Generate request for restoring bulk backup
  
``` shell
sgx_signer --seed "12 words seed of a whitelisted admin" --file /valid-path/backup.zip
```

* Generate request for restoring secret share of a nftid 
  
``` shell
sgx_signer --seed "12 words seed of a whitelisted admin" --nftid 13098
```
