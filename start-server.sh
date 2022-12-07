
ENV_FILE=${ENV_FILE:-/etc/default/sgx-server}

if [ ! -f $ENV_FILE ]
then
  export $(cat $ENV_FILE | xargs)
fi


PORT=${PORT:-8100}
HTTPS_PUBLIC_KEY=${HTTPS_PUBLIC_KEY:-/opt/sgx_server/cert.pem}
HTTPS_PRIVATE_KEY=${HTTPS_PRIVATE_KEY:-/opt/sgx_server/key.pem}
NFT_SERCRETS_PATH=${NFT_SERCRETS_PATH:-/opt/sgx_server_nft/}
TERNOA_ACCOUNT_KEY=${TERNOA_ACCOUNT_KEY:-/opt/sgx_server/ternoa_account.key}
ENCLAVE_IDENTITY=${ENCLAVE_IDENTITY:-C1N1E1}

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

while :; do
    case $1 in
        -p|--port)
			if [ "$2" ]; then
				PORT=$2
				shift
			else
				die 'ERROR: "--port" requires a non-empty option argument.'
			fi
        ;;
        -c|--cert)
			if [ "$2" ]; then
				HTTPS_PUBLIC_KEY=$2
				shift
			else
				die 'ERROR: "--cert" requires a non-empty option argument.'
			fi
        ;;
        -s|--key)
			if [ "$2" ]; then
				HTTPS_PRIVATE_KEY=$2
				shift
			else
				die 'ERROR: "--key" requires a non-empty option argument.'
			fi
        ;;
        -n|--secrets)
			if [ "$2" ]; then
				NFT_SERCRETS_PATH=$2
				shift
			else
				die 'ERROR: "--secrets" requires a non-empty option argument.'
			fi
        ;;
        -a|--account)
			if [ "$2" ]; then
				TERNOA_ACCOUNT_KEY=$2
				shift
			else
				die 'ERROR: "--account" requires a non-empty option argument.'
			fi
        ;;
		-i|--identity)
			if [ "$2" ]; then
				ENCLAVE_IDENTITY=$2
				shift
			else
				die 'ERROR: "--identity" requires a non-empty option argument.'
			fi
		;;
        *) break
    esac
    shift
done


echo "port: $PORT"
echo "public key: $HTTPS_PUBLIC_KEY"
echo "private key: $HTTPS_PRIVATE_KEY"
echo "nft secrets: $NFT_SERCRETS_PATH"
echo "account key: $TERNOA_ACCOUNT_KEY"
echo "encalve name: $ENCLAVE_IDENTITY"


# Compiling the source code
/home/ubuntu/.cargo/bin/cargo build --release

# Create Enclave using Makefile
make 	SGX=1 \
		SGX_PORT=$PORT \
		SGX_TLS_CERT=$HTTPS_PUBLIC_KEY \
		SGX_TLS_KEY=$HTTPS_PRIVATE_KEY \
		SGX_SEAL_PATH=$NFT_SERCRETS_PATH \
		SGX_OWNER_KEY=$TERNOA_ACCOUNT_KEY \
		SGX_IDENTITY=$ENCLAVE_IDENTITY \
		start-gramine-server >> make.log 2>&1 &

echo -n "Initializing encalve ..."
while ! (test -f "enclave.log") || ! (grep -q "Port $(PORT)" "enclave.log"); do
	echo -n "."
	sleep 1
done

echo -e "\n"
echo "Getting Report from IAS ..."

./generate-ias-report.sh

echo "IAS Report is ready."
