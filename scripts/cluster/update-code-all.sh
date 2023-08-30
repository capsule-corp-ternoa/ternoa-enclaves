echo -e "\nWARN! You may need to run with SUDO ."
echo -e "Input argument to this script is the name of the cluster folder."
echo -e "Example: sudo ./update-code-all.sh source/bin destination/bin"


update_enclave() {
  printf 'Updating : "%s"\n' "$2" >&2
  cd "$2"
  cp "$1/gramine/bin" gramine/ -rf
  cd ..
}

if [ -z "$1" ]
then
    echo "Source is not provided"
    exit
fi

if [ -z "$2" ]
then
    echo "Destination is not provided"
    exit
else
    cd "$2"
fi

for enclave in *
do
    update_enclave "$1" "$enclave"
    echo -e "\n"
done


cd ..
