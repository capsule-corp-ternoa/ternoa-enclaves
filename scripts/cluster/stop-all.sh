echo -e "\nWARN! You may need to run with SUDO ."
echo -e "Input arguments to this script are unique identifiers (i.e port) of enclaves to be stopped."
echo -e "Example: sudo ./stop-all.sh 8101 8102 8103 8104\n" 

stop_enclave() {
    printf 'Stopping enclave with identifier : "%s"\n' "$1" >&2
    ps aux | grep "$1" | grep -v grep | awk '{ print $2}' | xargs kill -9
}

die () {
    printf '%s\n' "$1" >&2
    exit
}

for id in "$@"
do
    stop_enclave "$id"
done


