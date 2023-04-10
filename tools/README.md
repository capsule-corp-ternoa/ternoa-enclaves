Compile the binary for your desired chain, i.e dev-0, alphanet, mainnet

``` shell
cargo build --release --no-default-features --features dev-0
``` 
default feature is alphanet.

Run the program with a whitelisted seed-phrase and input zip-file 

``` shell

./target/release/sgx_signer --seed "hockey fine ... egg sibling" --file ../test/test.zip
```
