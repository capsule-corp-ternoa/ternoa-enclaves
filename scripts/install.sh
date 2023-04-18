# ----- Driver for old kernels
#wget https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_driver_2.11.054c9c4c.bin
#sudo chmod +x sgx_linux_x64_driver_2.11.054c9c4c.bin
#sudo ./sgx_linux_x64_driver_2.11.054c9c4c.bin
#sudo /sbin/depmod
#sudo /sbin/modprobe isgx
#lsmod | grep sgx

# ----- Ubuntu
sudo apt update

sudo apt install build-essential python2 ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl dkms linux-headers-$(uname -r) -y
sudo apt install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev protobuf-c-compiler libprotobuf-c-dev lsb-release libsystemd0 -y

sudo apt install jq -y

# ----- Node.JS for PCCS
#sudo apt install dkms -y
#curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash
#export NVM_DIR="$HOME/.nvm"
#[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
#[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion
#nvm install node
#sudo apt install cracklib-runtime -y
#sudo apt --fix-broken install -y

# ----- Rust
sudo apt install clang llvm pkg-config nettle-dev -y
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup update
 
 # Rust for sudo
sudo su
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup update
exit

# ----- Subxt
cargo install subxt-cli

# ----- Linux-sgx
git clone https://github.com/intel/linux-sgx.git
cd linux-sgx
make preparation
sudo cp external/toolset/ubuntu20.04/* /usr/local/bin

# ----- Linux-sgx-sdk
# Simple Way
# wget https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.19.100.3.bin
# sudo chmod +x sgx_linux_x64_sdk_2.19.100.3.bin
# sudo ./sgx_linux_x64_sdk_2.19.100.3.bin

# Hard Way
make clean
make sdk_install_pkg
sudo chmod +x ./linux/installer/bin/sgx_linux_x64_sdk_2.19.100.3.bin
cp ./linux/installer/bin/sgx_linux_x64_sdk_2.19.100.3.bin ~

sudo chown ubuntu:ubuntu /opt
../sgx_linux_x64_sdk_2.19.100.3.bin --prefix /opt
source /opt/sgxsdk/environment

# ----- Linux-sgx-psw
sudo apt remove sgx-*
sudo apt remove libsgx-*
sudo touch /etc/aesmd.conf

make clean
make deb_psw_pkg
#make psw_install_pkg
#sudo chmod +x ./linux/installer/bin/sgx_linux_x64_psw_2.19.100.3.bin
#cp ./linux/installer/bin/sgx_linux_x64_psw_2.19.100.3.bin ~
#sudo ../linux/installer/bin/sgx_linux_x64_psw_2.19.100.3.bin

mkdir ~/psw
cp $(find . -name "*.deb") ~/psw
#or
#make deb_local_repo

sudo dpkg -i ~/psw/libsgx-headers_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-quote-ex_2.19.100.3-jammy1_amd64.deb    
sudo dpkg -i ~/psw/libsgx-quote-ex-dev_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-enclave-common_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-enclave-common-dev_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-urts_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-ae-pce_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-pce-logic_1.16.100.2-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-epid_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-epid-dev_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-launch_2.19.100.3-jammy1_amd64.deb 
sudo dpkg -i ~/psw/libsgx-launch-dev_2.19.100.3-jammy1_amd64.deb  
sudo dpkg -i ~/psw/sgx-aesm-service_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-ae-epid_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-aesm-pce-plugin_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-aesm-epid-plugin_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-uae-service_2.19.100.3-jammy1_amd64.deb
sudo dpkg -i ~/psw/libsgx-ae-le_2.19.100.3-jammy1_amd64.deb 
sudo dpkg -i ~/psw/libsgx-aesm-launch-plugin_2.19.100.3-jammy1_amd64.deb    

# Enter

# --- DCAP 
#sudo dpkg -i ~/psw/libsgx-ae-id-enclave_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-ae-qe3_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-ae-qve_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-qe3-logic_1.16.100.3-jammy1_amd64.deb   
#sudo dpkg -i ~/psw/libsgx-ae-tdqe_1.16.100.3-jammy1_amd64.deb    
#sudo dpkg -i ~/psw/libtdx-attest_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libtdx-attest-dev_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-ra-network_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-ra-uefi_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-ra-uefi-dev_1.16.100.3-jammy1_amd64.deb      
#sudo dpkg -i ~/psw/libsgx-aesm-ecdsa-plugin_2.19.100.3-jammy1_amd64.deb     
#sudo dpkg -i ~/psw/libsgx-aesm-quote-ex-plugin_2.19.100.3-jammy1_amd64.deb  
#sudo dpkg -i ~/psw/libsgx-tdx-logic_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-tdx-logic-dev_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/sgx-pck-id-retrieval-tool_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/sgx-ra-service_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/tdx-qgs_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-dcap-ql_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-dcap-quote-verify-dev_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-dcap-quote-verify_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-dcap-default-qpl_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/libsgx-dcap-default-qpl-dev_1.16.100.3-jammy1_amd64.deb
#sudo dpkg -i ~/psw/sgx-dcap-pccs_1.16.100.3-jammy1_amd64.deb

# NOTE: for DCAP we should install libsgx-dcap-ql instead
# NOTE: for DCAP we should install libsgx-quote-ex instead
 

# ----- Gramine
sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ stable main' | sudo tee /etc/apt/sources.list.d/gramine.list

curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update -y
sudo apt install gramine -y
is-sgx-available
gramine-sgx-gen-private-key
sudo cp -r ~/.config /root/

# ----- Python Substrate Interface
pip install --upgrade pip
pip install "scalecodec>=1.1.2"
pip install substrate-interface
pip install base58

# ----- cosign
wget "https://github.com/sigstore/cosign/releases/download/v1.6.0/cosign_1.6.0_amd64.deb"
sudo dpkg -i cosign_1.6.0_amd64.deb
sudo mv /usr/local/bin/cosign-linux-amd64 /usr/local/bin/cosign

# ----- Ternoa
cd ~
git clone https://github.com/capsule-corp-ternoa/sgx_server.git
cd sgx_server

# NOTE: On new DOMAIN, credentials/certificates will be invalid, you'll need to remove them before start
# NOTE: For production, please be careful about certs, never delete them, because every domain has 5 times quota every week.
# NOTE: It takes 20 seconds for sgx_server to start, that's because of fetch new certificates.

# --dev         builds and signs the binary everytime, so you need to provide password for signing with cosign private-key.
# --release     downloads binary and signature from Ternoa github repository
# --domain      is critical for certificates of tls/https 
# --port        different enclaves on the same machine need to have different ports

cargo build --release --no-default-features --features alphanet
sudo scripts/clear-server.sh
sudo CHAIN="alphanet" ./scripts/start-server.sh --domain alphanet-c1n1v2.ternoa.dev --port 8100 --identity ALPHANET-C1N1V2EI --dev


 #sudo CHAIN="alphanet" ./scripts/start-server.sh --domain alphanet-c1n1v2.ternoa.dev --port 8100 --identity ALPHANET-C1N1V2EI --release

# You can test the server on the specific DOMAIN and PORT with
curl -s https://mainnet-c1n1.ternoa.network:8100/api/health | jq .

# You can stop the server on the specific PORT and clean intermediate files with :
#sudo scripts/stop-server.sh -p 8100


