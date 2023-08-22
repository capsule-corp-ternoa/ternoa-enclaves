# Ternoa Enclave Signer Tool

A tool to generate signed json body to be used for in Postman/cUrl requests to Ternoa sgx enclave API endpoints.

## Build

Compile the binary for your desired chain, i.e dev-0, alpha-net, main-net

default feature is alpha-net.

``` shell
cargo build --release --no-default-features --features main-net
```

## Run

Options:

  --request  &emsp;&emsp;  Can be "retrieve | store" for secrets or "fetch-bulk | push-bulk | fetch-id | push-id" for backup

  --seed SEED-PHRASE &emsp;&emsp; Admin Enclave or NFT-Owner Seed Phrase

  --file FILE-PATH  &emsp;&emsp;  Path to (ZIP-) File, containing sealed NFT key-shares for backups

  --nftid NFTID  &emsp;&emsp;  NFT-ID for storing/retrieving keyshares in enclave
  
  --id_vec  &emsp;&emsp;  A vector of nft-id or filename_keyshare for Id-based Admin backup

  --secret_share  &emsp;&emsp;  Custom keyshare for storing in enclave

  --block_number  &emsp;&emsp;  Custom blocknumber to be used in Add/Retrieve keyshares to enclaves

  --expire  &emsp;&emsp;  Custom expiration period to be used in Add/Retrieve keyshares to enclaves

  -- custom_data  &emsp;&emsp;  Custom full data to be used in Add/Retrieve keyshares to enclaves

* Generate request for bulk backup
  
``` shell
sgx_signer --request fetch-bulk --seed "12 words seed of a whitelisted admin" --file /backups/download-enclave.zip
```

* Generate request for bulk restore
  
``` shell
sgx_signer --request push-bulk --seed "12 words seed of a whitelisted admin" --file /backups/upload-secrets.zip
```

* Generate request for id-based backup
  
``` shell
sgx_signer --request fetch-id --seed "12 words seed of a whitelisted admin" --id-vec [12,134,340]
```

* Generate request for id-based restore
  
``` shell
sgx_signer --request push-id --seed "12 words seed of a whitelisted admin" --id-vec ["nft_12_45678_NFT12SECRETPART","capsule_134_56789_CAPSULE134SECRETPART"]
```

* Generate request for retrieving secret share of a nftid with default parameters
  
``` shell
sgx_signer --request retrieve --seed "12 words seed of a whitelisted admin" --nftid 13
```

* Generate request for storing/setting secret share of a nftid with default parameters
  
``` shell
sgx_signer --request store --seed "12 words seed of a whitelisted admin" --nftid 13
```

* Generate request for storing/setting secret share of a nftid with detailed parameters
  
``` shell
sgx_signer --request store --seed "12 words seed of a whitelisted admin" --nftid 13 --block-number 456788 --expire 15 --secret-share THIS-IS-A-VERY-SECRET-DATA!
```

* Generate request for storing/retrieving secret share of a nftid with custome data part
  
``` shell
sgx_signer --request store --seed "12 words seed of a whitelisted admin" --custome-data "IT-can-be-anything-but-it's-better-to-conform-a-pattern|nftid-secret-blocknumber-expiration|123_SECRETDATA_456789_12"
```
