#!/bin/bash

# ASSETS STRUCTURE
BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )
SCRIPTS_PATH=$BASEDIR/scripts
GRAMINE_PATH=$BASEDIR/gramine
SEAL_PATH=$GRAMINE_PATH/nft
CERT_PATH=$BASEDIR/credentials/certificates
QUOTE_PATH=$GRAMINEPATH/quote
CREDENTIALS_PATH=$BASEDIR/credentials

# DEFAULT VALUES
DOMAIN=${DOMIAN:-dev-c1n1.ternoa.network}
PORT=${PORT:-8101}
MACHINE_DOMAIN=$(awk -e '$2 ~ /.+\..+\..+/ {print $2}' /etc/hosts)
NFT_SERCRETS_PATH=${NFT_SERCRETS_PATH:-$SEAL_PATH}
# PASSWORD = Test123456
#TERNOA_ACCOUNT_PATH=${TERNOA_ACCOUNT_KEY:-$ACCOUNTS_PATH/owner_account.json} 
ENCLAVE_IDENTITY=${ENCLAVE_IDENTITY:-C1N1E1}

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
        -n|--secrets)
	    if [ "$2" ]; then
		NFT_SERCRETS_PATH=$2
		shift
	    else
		die 'ERROR: "--secrets" requires a non-empty option argument.'
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
	-v|--verbose)
		if [ "$2" ]; then
		VERBOSITY_LEVLE=$2
		shift
		else
		die 'ERROR: "--verbosity" requires a non-empty option argument.'
		fi
	;;
	-h|--help)
	    echo -e "usage: start-server.h <OPTIONS> \n\n OPTIONS: \n -d | --domain <server domain name> \n -p | --port <port-number> \n -s | --secrets <Seal Path> \n -i | --identity <Optional Enclave Name> "
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
#echo -e "\n\n${BIWhite}Importing the account${NC}"
#TERNOA_ACCOUNT_KEY="$(python $SCRIPTS_PATH/import_account.py $TERNOA_ACCOUNT_PATH)"
#if [ -z "$TERNOA_ACCOUNT_KEY" ]; then
#    echo -e "${IRed}Can not decode account file${NC}"
#    exit
#fi

echo -e "\nport:\t\t ${IGreen}$PORT${NC}"
echo -e "domain name:\t ${IGreen}$DOMAIN${NC}"
echo -e "nft secrets:\t ${IGreen}$NFT_SERCRETS_PATH${NC}"
echo -e "enclave name:\t ${IGreen}$ENCLAVE_IDENTITY${NC}"
echo -e "account key:\t ${IGreen}$TERNOA_ACCOUNT_PATH${NC}" # WILL BE REPLACED BY GITHUB SCRIPT

# Create Enclave using Makefile
cd $GRAMINE_PATH
echo -n -e "\n${BIWhite}Creating Enclave ${NC}"
make 	SGX=1 \
	SGX_DOMAIN=$DOMAIN \
	SGX_PORT=$PORT \
	SGX_BASE_PATH=$BASEDIR \
	SGX_SEAL_PATH=$NFT_SERCRETS_PATH \
	SGX_QUOTE_PATH=$QUOTE_PATH \
	SGX_CREDENTIALS_PATH=$CREDENTIALS_PATH \
	SGX_CERT_PATH=$CERT_PATH \
	SGX_IDENTITY=$ENCLAVE_IDENTITY \
	SGX_VERBOSITY=$VERBOSITY_LEVLE\
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

#echo -e "\n${BIWhite}Getting Report from IAS${NC}"

#$SCRIPTS_PATH/generate-ias-report.sh

#echo "IAS Report is ready."

echo -e "\n"
