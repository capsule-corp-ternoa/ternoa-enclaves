echo -e "\nWARN! You may need to run with SUDO ."
echo -e "Input argument to this script is the name of the cluster folder."
echo -e "Example: sudo ./clear-all.sh ./cluster_old_0\n"


clear_enclave() {
  printf 'Cleaning : "%s"\n' "$1" >&2
  cd "$1"
  #./scripts/clear-server.sh
  rm gramine/*.log gramine/*.manifest gramine/*.sgx gramine/*.sig gramine/certificates/*
  rm ./gramine/bin/*
  rm ./gramine/nft/*.log
  rm ./gramine/nft/*.keyshare
  rm ./gramine/nft/sync.state
  touch ./gramine/nft/sync.state
  rm start.log
  cd ..
}

if [ -z "$1" ]
then
    echo "Not enough input arguments"
    exit
else
    cd "$1"
fi
   
for enclave in *
do
    clear_enclave "$enclave"
    echo -e "\n"
done


cd ..
