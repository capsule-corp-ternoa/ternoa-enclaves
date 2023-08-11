#!/bin/bash
<<LICENSE
Copyright 2021 Ternoa.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
LICENSE

if [ -z $1 ]; then 
  echo "Error! please provide a 'Chain name' i.e alphanet, mainnet, dev-0"
  exit
else
  CHAIN=$1
  echo "Chain = $CHAIN"
fi

# ASSETS STRUCTURE
BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )
SCRIPTS_PATH=$BASEDIR/scripts
GRAMINE_PATH=$BASEDIR/gramine

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

if [ -z "$(which cargo)" ]
then
/home/ubuntu/.cargo/bin/cargo build --release --no-default-features --features $CHAIN
else
cargo build --release --no-default-features --features $CHAIN
fi

mkdir -p $GRAMINE_PATH/bin/
rm $GRAMINE_PATH/bin/*
cp -f $BASEDIR/target/release/sgx_server $GRAMINE_PATH/bin/

echo "signing the binary ..."
COSIGN_PASSWORD="Test123456" cosign sign-blob --key $BASEDIR/credentials/keys/dev/cosign.key $GRAMINE_PATH/bin/sgx_server --output-file $GRAMINE_PATH/bin/sgx_server.sig
tr -d '\n' < $GRAMINE_PATH/bin/sgx_server.sig > sgx_server.sig
mv sgx_server.sig $GRAMINE_PATH/bin/sgx_server.sig