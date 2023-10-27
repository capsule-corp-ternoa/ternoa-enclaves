#!/bin/bash

# ASSETS STRUCTURE
BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )
SCRIPTS_PATH=$BASEDIR/scripts
GRAMINE_PATH=$BASEDIR/gramine

# DEFAULT VALUES
CHAIN=${CHAIN:-alphanet}

DOMAIN=${DOMIAN:-subdomain.your-domain.com}
PORT=${PORT:-8000}

MACHINE_DOMAIN=$(awk -e '$2 ~ /.+\..+\..+/ {print $2}' /etc/hosts)

VERBOSITY_LEVLE=3
DEV_BUILD=0

# OVERWRITE WITH PRODUCTION VALUES
#ENV_FILE=${ENV_FILE:-/etc/default/sgx-server}
#SGX_SERVER_ENV_FILE=?

#if [ -f $SGX_SERVER_ENV_FILE ]; then
#  export $(cat $SGX_SERVER_ENV_FILE | xargs)
#fi

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
	-v|--verbose)
	if [ "$2" ]; then
		VERBOSITY_LEVLE=$2
		shift
	    else
		die 'ERROR: "--verbosity" requires a non-empty option argument.'
	    fi
	;;
	-h|--help)
	    echo -e "usage: start-server.h <OPTIONS> \n\n OPTIONS: \n [-d | --dev] [-r | --release] \n -d | --domain <server domain name> \n -p | --port <port-number> \n"
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
	ENCLAVE_DIR=$GRAMINE_PATH \
	SGX_DOMAIN=$DOMAIN \
	SGX_PORT=$PORT \
	SGX_VERBOSITY=$VERBOSITY_LEVLE\
	SGX_DEV_BUILD=$DEV_BUILD\
	start-gramine-server #>> $GRAMINE_PATH/make.log 2>&1 &


