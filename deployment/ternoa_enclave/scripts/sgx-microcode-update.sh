family=$(printf '%02x' $(lscpu | awk '/CPU\sfamily:/{print $3}'))
model=$(printf '%02x' $(lscpu | awk '/Model:/{print $2}'))
stepping=$(printf '%02x' $(lscpu | awk '/Stepping:/{print $2}'))
filename="$family-$model-$stepping"

wget "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/raw/main/intel-ucode/$filename"
sudo cp -r /lib/firmware/intel-ucode /lib/firmware/intel-ucode.back
echo "OLD MICROCODE INFO :"
iucode_tool -l "/lib/firmware/intel-ucode/$filename"
sudo rm -r "/lib/firmware/intel-ucode/$filename"

sudo cp $filename /lib/firmware/intel-ucode
echo "NEW MICROCODE INFO :"
iucode_tool -l "/lib/firmware/intel-ucode/$filename"

echo "UPDATE KERNEL IMAGE:"
sudo update-initramfs -c -k $(uname -r)

echo -e "\n-------------------------\n"
echo "IF ERROR, DO NEXT OPERATIONS MANUALLY"
echo "$(blkid)"
echo "LOOK FOR SWAP : ........... UUID="...." TYPE="swap" ......."
echo "PUT THE UUID FROM ABOVE TO NEXT COMMAND"
echo "printf 'RESUME=UUID=d5b32af6-2f61-498a-acf8-a9895e2a509a' | sudo tee /etc/initramfs-tools/conf.d/resume"
echo  "RETRY : sudo update-initramfs -c -k $(uname -r)"

echo -e "\n THEN\n"
echo -e "\n ---- REBOOT -----\n"