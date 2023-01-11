
# ASSETS STRUCTURE
BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )
SCRIPTS_PATH=$BASEDIR/scripts/
GRAMINE_PATH=$BASEDIR/gramine/
SEAL_PATH=$GRAMINE_PATH/nft/
CERT_PATH=$BASEDIR/credentials/certificates/
ACCOUNTS_PATH=$BASEDIR/credentials/accounts/
QUOTE_PATH=$BASEDIR/credentials/quote/

# DEFAULT VALUES
PORT=${PORT:-8101}
MACHINE_DOMAIN=$(awk -e '$2 ~ /.+\..+\..+/ {print $2}' /etc/hosts)
HTTPS_PUBLIC_KEY=${HTTPS_PUBLIC_KEY:-$CERT_PATH/server_cert.pem}
HTTPS_PRIVATE_KEY=${HTTPS_PRIVATE_KEY:-$CERT_PATH/server_key.pem}
NFT_SERCRETS_PATH=${NFT_SERCRETS_PATH:-$SEAL_PATH}
TERNOA_ACCOUNT_PATH=${TERNOA_ACCOUNT_KEY:-$ACCOUNTS_PATH/owner_account.json} # PASSWORD = Test123456
TERNOA_ACCOUNT_KEY=
ENCLAVE_IDENTITY=${ENCLAVE_IDENTITY:-C1N1E1}

# VALID CERTIFICATES
VALIDCERT_PATH=/etc/letsencrypt/live/
if [ -d "$VALIDCERT_PATH" ]; then
    CERTBASE=/etc/letsencrypt/live/
    DOMAIN=$(ls $CERTBASE | grep ternoa)
    CERT_PATH=$CERTBASE/$DOMAIN/
    HTTPS_PUBLIC_KEY=$CERT_PATH/cert.pem
    HTTPS_PRIVATE_KEY=$CERT_PATH/privkey.pem
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

	    cp -f $BASEDIR/target/release/sgx_server $GRAMINE_PATH/bin/
	    cat $GRAMINE_PATH/bin/sgx_server | sha256sum | sed -e 's/\s.*$//' | xargs -I{} sh -c  'echo "$1" > /tmp/checksum' -- {}
		mv /tmp/checksum $GRAMINE_PATH/bin/checksum
		cosign sign-blob --key $BASEDIR/credentials/keys/cosign.key $GRAMINE_PATH/bin/sgx_server --output-file $GRAMINE_PATH/bin/sgx_server.sig
	;;
	-h|--help)
	    echo "usage: start-server.h --port <port-number> --cert <TLS Cert Path> --key <TLS Private Key Path> --secrets <Seal Path> --account <Ternoa Account Json File> --identity <Arbitraty Enclave Name> [-b|--build]"
	    exit 0
	    ;;
        *) break
    esac
    shift
done

NC='\033[0m'			  # Reset
IRed='\033[0;91m'         # Red
IGreen='\033[0;92m'       # Green
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White
BIWhite='\033[1;97m'      # White

# Import Keypair from account
echo -e "\n\n${BIWhite}Importing the account${NC}"
TERNOA_ACCOUNT_KEY="$(python $SCRIPTS_PATH/import_account.py $TERNOA_ACCOUNT_PATH)"
if [ -z "$TERNOA_ACCOUNT_KEY" ]; then
    echo -e "${IRed}Can not decode account file${NC}"
    exit
fi

echo -e "\nport:\t\t ${IGreen}$PORT${NC}"
echo -e "domain name:\t ${IGreen}$DOMAIN${NC}"
echo -e "public key:\t ${IGreen}$HTTPS_PUBLIC_KEY${NC}"
echo -e "private key:\t ${IGreen}$HTTPS_PRIVATE_KEY${NC}"
echo -e "nft secrets:\t ${IGreen}$NFT_SERCRETS_PATH${NC}"
echo -e "account key:\t ${IGreen}$TERNOA_ACCOUNT_PATH${NC}"
echo -e "encalve name:\t ${IGreen}$ENCLAVE_IDENTITY${NC}"

# Create Enclave using Makefile
cd $GRAMINE_PATH
echo -n -e "\n${BIWhite}Creating Encalve "
make 	SGX=1 \
	SGX_PORT=$PORT \
	SGX_BASE_PATH=$BASEDIR \
	SGX_TLS_CERT=$HTTPS_PUBLIC_KEY \
	SGX_TLS_KEY=$HTTPS_PRIVATE_KEY \
	SGX_SEAL_PATH=$NFT_SERCRETS_PATH \
	SGX_QUOTE_PATH=$QUOTE_PATH \
	SGX_CERT_PATH=$CERT_PATH \
	SGX_OWNER_KEY=$TERNOA_ACCOUNT_KEY \
	SGX_IDENTITY=$ENCLAVE_IDENTITY \
	start-gramine-server >> $GRAMINE_PATH/make.log 2>&1 &

cd $BASEDIR

COUNTER=0
while ! (test -f "$GRAMINE_PATH/make.log") || ! (grep -q "enclave.log" "$GRAMINE_PATH/make.log"); do
    echo -n "."
    sleep 1
    let COUNTER=$COUNTER+1
    if [ $COUNTER -ge 10 ]; then
	break
    fi
done

echo -e "\n${NC}View ${IBlue}gramine/make.log${NC} for enclave details."

COUNTER=0
echo -n -e "\n${BIWhite}Initializing Encalve "
while ! (test -f "$GRAMINE_PATH/enclave.log") || ! (grep -q "Port $PORT" "$GRAMINE_PATH/enclave.log"); do
    echo -n "."
    sleep 1
    let COUNTER=$COUNTER+1
    if [ $COUNTER -ge 10 ]; then
	break
    fi
done

echo -e "\n${NC}View ${IBlue}gramine/enclave.log${NC} for server details."

#echo -e "\n${BIWhite}Getting Report from IAS${NC}"

#$SCRIPTS_PATH/generate-ias-report.sh

#echo "IAS Report is ready."

echo -e "\n"
