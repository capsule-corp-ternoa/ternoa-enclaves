docker build --rm --no-cache \
    -t ternoa-sgx:v0.4.4-alphanet \
    -t ternoa-sgx:latest \
    --build-arg UBUNTU_VERSION=22.04 \
    --build-arg ENCLAVE_CHAIN=alphanet \
    --build-arg CODE_VERSION=v0.4.4 \
    .
