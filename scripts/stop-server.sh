BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )/
SCRIPTSPATH="$BASEDIR/scripts/"
CERTPATH="$BASEDIR/credentials/certificates/"
SEALPATH="$BASEDIR/credentials/nft/"
ACCOUNTSPATH="$BASEDIR/credentials/accounts/"
GRAMINEPATH="$BASEDIR/gramine/"

# DEFAULT VALUES
PORT=${PORT:-8101}
HTTPS_PUBLIC_KEY=${HTTPS_PUBLIC_KEY:-$CERTPATH/server_cert.pem}
HTTPS_PRIVATE_KEY=${HTTPS_PRIVATE_KEY:-$CERTPATH/server_key.pem}
NFT_SERCRETS_PATH=${NFT_SERCRETS_PATH:-$SEALPATH}
TERNOA_ACCOUNT_PATH=${TERNOA_ACCOUNT_KEY:-$ACCOUNTSPATH/ternoa_account.json} # PASSWORD = TEST123456
TERNOA_ACCOUNT_KEY=
ENCLAVE_IDENTITY=${ENCLAVE_IDENTITY:-C1N1E1}

stop_enclave() {
    printf 'stop enclave with identifier : "%s"\n' "$1" >&2
    ps aux | grep "$1" | awk '{ print $2}' | xargs kill -9
}

die () {
    printf '%s\n' "$1" >&2
    exit
}

while :; do
    case $1 in
        -i|--identity)
	    if [ "$2" ]; then
		ENCLAVE_ID="identity $2"
                stop_enclave "$ENCLAVE_ID"
		shift
	    else
		die 'ERROR: "--identity" requires a non-empty option argument.'
	    fi
            ;;
        -p|--port)
	    if [ "$2" ]; then
		PORTID="port $2"
                stop_enclave "$PORTID"
		shift
	    else
		die 'ERROR: "--port" requires a non-empty option argument.'
	    fi
            ;;
        *) break
    esac
    shift
done

#find . -name *~ | xargs rm
rm $BASEDIR/credentials/quote/*

cd $GRAMINEPATH
make clean
cd $BASEDIR