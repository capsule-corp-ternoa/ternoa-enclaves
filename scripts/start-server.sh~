
# ASSETS STRUCTURE
BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )/
SCRIPTSPATH=$BASEDIR/scripts/
CERTPATH=$BASEDIR/credentials/certificates/
SEALPATH=$BASEDIR/credentials/nft/
ACCOUNTSPATH=$BASEDIR/credentials/accounts/
GRAMINEPATH=$BASEDIR/gramine/
QUOTEPATH=$BASEDIR/credentials/quote/

# DEFAULT VALUES
PORT=${PORT:-8101}
MACHINE_DOMAIN=$(awk -e '$2 ~ /.+\..+\..+/ {print $2}' /etc/hosts)
HTTPS_PUBLIC_KEY=${HTTPS_PUBLIC_KEY:-$CERTPATH/server_cert.pem}
HTTPS_PRIVATE_KEY=${HTTPS_PRIVATE_KEY:-$CERTPATH/server_key.pem}
NFT_SERCRETS_PATH=${NFT_SERCRETS_PATH:-$SEALPATH}
TERNOA_ACCOUNT_PATH=${TERNOA_ACCOUNT_KEY:-$ACCOUNTSPATH/owner_account.json} # PASSWORD = Test123456
TERNOA_ACCOUNT_KEY=
ENCLAVE_IDENTITY=${ENCLAVE_IDENTITY:-C1N1E1}

# VALID CERTIFICATES
VALIDCERT_PATH=/etc/letsencrypt/live/
if [ -d "$VALIDCERT_PATH" ]; then
    CERTBASE=/etc/letsencrypt/live/
    DOMAIN=$(ls $CERTBASE | grep ternoa)
    CERTPATH=$CERTBASE/$DOMAIN/
    HTTPS_PUBLIC_KEY=$CERTPATH/cert.pem
    HTTPS_PRIVATE_KEY=$CERTPATH/privkey.pem
else
    echo "$VALIDCERT_PATH directory does not exist. Self-signed certificate will be used."
fi

# OVERWRITE WITH PRODUCTION VALUES
ENV_FILE=${ENV_FILE:-/etc/default/sgx-server}
SGX_SERVER_ENV_FILE=?

if [ -f $SGX_SERVER_ENV_FILE ]; then
  export $(cat $SGX_SERVER_ENV_FILE | xargs)
fi

# INPUT ARGUMENTS

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
		TERNOA_ACCOUNT_PATH=$2
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
	-b|--build)
	# Compiling the source code
	    if [ -z "$(which cargo)" ]
	    then
		/home/ubuntu/.cargo/bin/cargo build --release
	    else
		cargo build --release
	    fi
	    
	    cp -f $BASEDIR/target/release/sgx_server $BASEDIR/bin/
	    cat $BASEDIR/bin/sgx_server | sha256sum | sed -e 's/\s.*$//' | xargs -I{} sh -c  'echo "$1" > $BASEDIR/bin/SHA256' -- {}

	;;
	-h|--help)
	    echo "usage: start-server.h --port <port-number> --cert <TLS Cert Path> --key <TLS Private Key Path> --secrets <Seal Path> --account <Ternoa Account Json File> --identity <Arbitraty Enclave Name> [-b|--build]"
	    exit 0
	    ;;
        *) break
    esac
    shift
done

# Import Keypair from account
echo "Importing the account"
TERNOA_ACCOUNT_KEY="$(python $SCRIPTSPATH/import_account.py $TERNOA_ACCOUNT_PATH)"
if [ -z "$TERNOA_ACCOUNT_KEY" ]; then
    echo "Can not decode account file"
    exit
fi


echo "port: $PORT"
echo "domain name: $DOMAIN"
echo "public key: $HTTPS_PUBLIC_KEY"
echo "private key: $HTTPS_PRIVATE_KEY"
echo "nft secrets: $NFT_SERCRETS_PATH"
echo "account key: $TERNOA_ACCOUNT_PATH"
echo "encalve name: $ENCLAVE_IDENTITY"


# Create Enclave using Makefile
cd $GRAMINEPATH
echo -n "Creating Encalve ..."
make 	SGX=1 \
	SGX_PORT=$PORT \
	SGX_BASE_PATH=$BASEDIR \
	SGX_TLS_CERT=$HTTPS_PUBLIC_KEY \
	SGX_TLS_KEY=$HTTPS_PRIVATE_KEY \
	SGX_SEAL_PATH=$NFT_SERCRETS_PATH \
	SGX_QUOTE_PATH=$QUOTEPATH \
	SGX_CERT_PATH=$CERTPATH \
	SGX_OWNER_KEY=$TERNOA_ACCOUNT_KEY \
	SGX_IDENTITY=$ENCLAVE_IDENTITY \
	start-gramine-server >> $GRAMINEPATH/make.log 2>&1 &

cd $BASEDIR

COUNTER=0
while ! (test -f "$GRAMINEPATH/make.log") || ! (grep -q "enclave.log" "$GRAMINEPATH/make.log"); do
    echo -n "."
    sleep 1
    let COUNTER=$COUNTER+1
    if [ $COUNTER -ge 10 ]; then
	break
    fi
done

tail -n 20 $GRAMINEPATH/make.log


COUNTER=0
echo -n "Initializing Encalve ..."
while ! (test -f "$GRAMINEPATH/enclave.log") || ! (grep -q "Port $PORT" "$GRAMINEPATH/enclave.log"); do
    echo -n "."
    sleep 1
    let COUNTER=$COUNTER+1
    if [ $COUNTER -ge 10 ]; then
	break
    fi
done

cat $GRAMINEPATH/enclave.log

#echo -e "\n"
#echo "Getting Report from IAS ..."

#$SCRIPTSPATH/generate-ias-report.sh

#echo "IAS Report is ready."
