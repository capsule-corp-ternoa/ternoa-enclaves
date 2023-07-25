echo -e "\nWARN! You may need to run with SUDO ."
echo -e "Input argument to this script is the path to the cluster as well as five port number."
echo -e "Example: sudo ./start-all.sh ./cluster_old_0 8000 8001 8002 8003 8004 \n"


start_enclave() {
    printf 'Starting : "%s"\n' "$1" >&2
    cd "$1"
    CHAIN="dev-0" ./scripts/start-server.sh --domain dev-c1n1.ternoa.network  --port "$2" --dev --verbose 3 > start.log 2>&1 &
    cd ..
}

if [ -z "$1" ]                                                                                                                                         
then
    echo "Not enough input arguments"
    exit
else
    cd "$1"
    shift
fi

for enclave in *
do
    if [ -z "$1" ]                                                                                                                                     
    then
	echo "Not enough input arguments"
	exit
    fi

    start_enclave "$enclave" "$1"
    shift
    echo -e "\n--------------\n"
done

cd ..
