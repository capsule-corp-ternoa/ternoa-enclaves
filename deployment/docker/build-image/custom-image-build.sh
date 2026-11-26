# docker system prune -f
# docker builder prune -f

read -p "Building for which chain [mainnet, alphanet, dev0, dev1] : " chain
read -p "Building which version [>= v0.5.3-rc6] : " codever

CHAIN=${chain:-mainnet}
CODEVER=${codever:-v0.5.3-rc6}

docker build --rm --no-cache \
    -t capsulecorpternoa/ternoa-sgx:$CODEVER-$CHAIN \
    -t capsulecorpternoa/ternoa-sgx:latest \
    --build-arg UBUNTU_VERSION=22.04 \
    --build-arg ENCLAVE_CHAIN=$CHAIN \
    --build-arg CODE_VERSION=$CODEVER \
    .
