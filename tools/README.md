## Build
Compile the binary for your desired chain, i.e dev-0, alphanet, mainnet

default feature is alphanet.

here is a smaple for dev-0 chain :

``` shell
cargo build --release --no-default-features --features dev-0
``` 


## Run
Run the program with a whitelisted seed-phrase and input zip-file 

``` shell
./target/release/sgx_signer --seed "12 words seed of a whitelisted admin" --file <filepath> --nftid <u32>
```

The outputs are Signed Json body to be used in Postman/cUrl requests to enclave API endpoints.
