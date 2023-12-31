#!/bin/bash

# DEFAULT VALUES
PORT=${PORT:-8101}

stop_enclave() {
    printf 'stop enclave with identifier : "%s"\n' "$1" >&2
    ps aux | grep "$1" | grep -v grep | awk '{ print $2}' | xargs kill -9
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

