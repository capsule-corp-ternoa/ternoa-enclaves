echo -e "\nWARN! You may need to run with SUDO ."
echo -e "Input argument to this script is the name of the cluster folder."
echo -e "Example: sudo ./update-code-all.sh ./cluster_old_0\n"


update_enclave() {
  printf 'Updating : "%s"\n' "$1" >&2
  cd "$1"
  git add .
  git commit -m "save before fetch update."
  #git stash apply
  git pull -X theirs --all --no-edit
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
    update_enclave "$enclave"
    echo -e "\n"
done


cd ..
