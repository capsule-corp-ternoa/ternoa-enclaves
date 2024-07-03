# Ternoa Enclave Signer Tool

A tool to generate signed json body to be used for in Postman/cUrl requests to Ternoa sgx enclave API endpoints.

## Build

Compile the binary for your desired chain, i.e dev-0, alphanet, mainnet

default feature is alphanet.

``` shell
cargo build --release --no-default-features --features mainnet
```

## Run

Options:

  --request  &emsp;&emsp;  "retrieve | store" , "attest", "admin-fetch-bulk | admin-push-bulk | admin-fetch-id | admin-push-id"

  --seed SEED-PHRASE &emsp;&emsp; Admin Enclave or NFT-Owner Seed Phrase

  --file FILE-PATH  &emsp;&emsp;  Path to (ZIP-) File, containing sealed NFT key-shares for backups

  --nftid NFTID  &emsp;&emsp;  NFT-ID for storing/retrieving keyshares in enclave
  
  --id_vec  &emsp;&emsp;  A vector of nft-id or filename_keyshare for Id-based Admin backup

  --secret_share  &emsp;&emsp;  Custom keyshare for storing in enclave

  --block_number  &emsp;&emsp;  Custom blocknumber to be used in Add/Retrieve keyshares to enclaves

  --expire  &emsp;&emsp;  Custom expiration period to be used in Add/Retrieve keyshares to enclaves

  -- custom_data  &emsp;&emsp;  Custom full data to be used in Add/Retrieve keyshares to enclaves

  --enclave-url   &emsp;&emsp;  address of the enclave being attested

### User

* Generate request for retrieving secret share of a nftid with default parameters
  
``` shell
sgx_signer --request retrieve --seed "12 words seed of an nft owner" --nftid 13
```

* Generate request for storing/setting secret share of a nftid with default parameters
  
``` shell
sgx_signer --request store --seed "12 words seed of an nft owner" --nftid 13
```

* Generate request for storing/setting secret share of a nftid with detailed parameters
  
``` shell
sgx_signer --request store --seed "12 words seed of an nft owner" --nftid 13 --block-number 456788 --expire 15 --secret-share THIS-IS-A-VERY-SECRET-DATA!
```

* Generate request for storing/retrieving secret share of a nftid with custome data part
  
``` shell
sgx_signer --request store --seed "12 words seed of an nft owner" --custome-data "This-can-be-anything-but-it's-better-to-conform-a-pattern|nftid-secret-blocknumber-expiration|123_SECRETDATA_456789_12"
```

* Do a remote attestation on an enclave with ECDSA (DCAP) method
  
``` shell
sgx_signer --request attest --enclave-url https://address:port --seed "12 words seed to sign the request"
```

### Admin

* Generate request for bulk backup
  
``` shell
sgx_signer --request admin-fetch-bulk --seed "12 words seed of a whitelisted admin" --file /backups/download-enclave.zip
```

* Generate request for bulk restore
  
``` shell
sgx_signer --request admin-push-bulk --seed "12 words seed of a whitelisted admin" --file /backups/upload-secrets.zip
```

* Generate request for id-based backup
  
``` shell
sgx_signer --request admin-fetch-id --seed "12 words seed of a whitelisted admin" --id-vec [12,134,340]
```

* Generate request for id-based restore
  
``` shell
sgx_signer --request admin-push-id --seed "12 words seed of a whitelisted admin" --id-vec "[\"nft_1_123456_THIS-IS-SECRETPART\",\"capsule_2_13456_THIS-IS-SECRET-PART2\"]"
```