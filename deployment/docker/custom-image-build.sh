docker build --rm --no-cache \
    -t ternoa-sgx:v0.4.4-alphanet \
    -t ternoa-sgx:latest \
    --build-arg UBUNTU_VERSION=22.04 \
    --build-arg ENCLAVE_CHAIN=alphanet \
    --build-arg ENCLAVE_DOMAIN=enclave.domain.me \
    --build-arg ENCLAVE_PORT=8000 \
    --build-arg ENCLAVE_VERBOSITY=3 \
    .
