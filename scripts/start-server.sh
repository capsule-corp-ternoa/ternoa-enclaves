#!/bin/bash

# ASSETS STRUCTURE
BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )
SCRIPTS_PATH=$BASEDIR/scripts
GRAMINE_PATH=$BASEDIR/gramine
CERT_PATH=$GRAMINE_PATH/certificates
QUOTE_PATH=$GRAMINE_PATH/quote
CREDENTIALS_PATH=$BASEDIR/credentials

# DEFAULT VALUES
CHAIN=${CHAIN:-alphanet}

DOMAIN=${DOMIAN:-alphanet-c1n1v2.ternoa.dev}
PORT=${PORT:-8100}

MACHINE_DOMAIN=$(awk -e '$2 ~ /.+\..+\..+/ {print $2}' /etc/hosts)

VERBOSITY_LEVLE=2
DEV_BUILD=0

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
        -d|--domain)
	    if [ "$2" ]; then
		DOMAIN=$2
		shift
	    else
		die 'ERROR: "--domian" requires a non-empty option argument.'
	    fi
        ;;
		-p|--port)
	    if [ "$2" ]; then
		PORT=$2
		shift
	    else
		die 'ERROR: "--port" requires a non-empty option argument.'
	    fi
        ;;
	-d|--dev)
	# Compiling the source code
		if [ -z "$(which cargo)" ]
		then
			/home/ubuntu/.cargo/bin/cargo build --release --no-default-features --features $CHAIN
		else
			cargo build --release --no-default-features --features $CHAIN
		fi
		
		# Use dev-manifest template
		DEV_BUILD=1

		mkdir -p $GRAMINE_PATH/bin/
		cp -f $BASEDIR/target/release/sgx_server $GRAMINE_PATH/bin/

		echo "signing the binary ..."
	    COSIGN_PASSWORD="Test123456" cosign sign-blob --key $BASEDIR/credentials/keys/dev/cosign.key $GRAMINE_PATH/bin/sgx_server --output-file $GRAMINE_PATH/bin/sgx_server.sig
		tr -d '\n' < $GRAMINE_PATH/bin/sgx_server.sig > sgx_server.sig
		mv sgx_server.sig $GRAMINE_PATH/bin/sgx_server.sig
	;;
	-r|--release)
	# Download the binary from github
		mkdir -p $GRAMINE_PATH/bin/
		
		# Use release-manifest template
		DEV_BUILD=0
		
		echo "Downloading binary and signature from Ternoa github repository"
		$SCRIPTS_PATH/fetch-release.sh
		mv ./sgx_server $GRAMINE_PATH/bin/
	;;
	-v|--verbose)
	if [ "$2" ]; then
		VERBOSITY_LEVLE=$2
		shift
	    else
		die 'ERROR: "--verbosity" requires a non-empty option argument.'
	    fi
	;;
	-h|--help)
	    echo -e "usage: start-server.h <OPTIONS> \n\n OPTIONS: \n [-d | --dev] [-r | --release] \n -d | --domain <server domain name> \n -p | --port <port-number> \n -s | --secrets <Seal Path> \n -i | --identity <Optional Enclave Name> "
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

echo -e "\nport:\t\t ${IGreen}$PORT${NC}"
echo -e "domain name:\t ${IGreen}$DOMAIN${NC}"

# Create Enclave using Makefile
cd $GRAMINE_PATH
echo -n -e "\n${BIWhite}Creating Enclave ${NC}"
make 	SGX=1 \
	SGX_DOMAIN=$DOMAIN \
	SGX_PORT=$PORT \
	SGX_BASE_PATH=$BASEDIR \
	SGX_QUOTE_PATH=$QUOTE_PATH \
	SGX_CERT_PATH=$CERT_PATH \
	SGX_VERBOSITY=$VERBOSITY_LEVLE\
	SGX_DEV_BUILD=$DEV_BUILD\
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

if [ $COUNTER -ge 10 ]; then
	cat $GRAMINE_PATH/make.log
	exit
else
	echo -e "\n${NC}View ${IBlue}$GRAMINE_PATH/make.log${NC} for enclave details."
fi 

COUNTER=30
echo -n -e "\n${BIWhite}Initializing Enclave : "
tput sc
while ! (test -f "$GRAMINE_PATH/enclave.log") || ! (grep -q "$PORT" "$GRAMINE_PATH/enclave.log"); do
    tput sc
	tput rev
	echo -n "$COUNTER seconds"
	tput sgr0
	tput rc
    sleep 1
    let COUNTER=$COUNTER-1
    if [ $COUNTER -le 0 ]; then
	break
    fi
done

if [ $COUNTER -le 0 ]; then
	cat $GRAMINE_PATH/enclave.log
	exit
else
	echo -e "\n${NC}View ${IBlue}$GRAMINE_PATH/make.log${NC} for enclave details."
	
	echo -e "\nTesting the server health with this command : curl -s https://$DOMAIN:$PORT/api/health | jq ."
	curl -s https://$DOMAIN:$PORT/api/health | jq .
fi

echo -e "\n"