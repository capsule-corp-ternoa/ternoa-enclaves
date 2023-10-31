export SDK_VERSION="2.22.100.1"
export PSW_VERSION="1.18.100.1"

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
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup update
 
# Rust for sudo
sudo -- bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source "$HOME/.cargo/env" && rustup update'


# ----- Subxt
cargo install subxt-cli

# ----- Linux-sgx
git clone https://github.com/intel/linux-sgx.git
cd linux-sgx
make preparation
sudo cp external/toolset/ubuntu20.04/* /usr/local/bin

# ----- Linux-sgx-sdk

# **Simple Way**

# wget https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_sdk_$SDK_VERSION.bin
# sudo chmod +x sgx_linux_x64_sdk_$SDK_VERSION.bin
# sudo ./sgx_linux_x64_sdk_$SDK_VERSION.bin

# **Hard Way**
make clean
make sdk_install_pkg
sudo chmod +x ./linux/installer/bin/sgx_linux_x64_sdk_$SDK_VERSION.bin
cp ./linux/installer/bin/sgx_linux_x64_sdk_$SDK_VERSION.bin /opt

sudo chown ubuntu:ubuntu /opt
/opt/sgx_linux_x64_sdk_$SDK_VERSION.bin --prefix /opt
source /opt/sgxsdk/environment

# ----- Linux-sgx-psw
sudo apt remove sgx-*
sudo apt remove libsgx-*
sudo touch /etc/aesmd.conf

make clean
make deb_psw_pkg

# METHOD 1: Local Repo
ln -s /opt/sgxsdk/ /opt/intel/sgxsdk
make deb_local_repo
sudo echo "deb [trusted=yes arch=amd64] file:/opt/linux-sgx/linux/installer/deb/sgx_debian_local_repo jammy main" >> /etc/apt/sources.list
sudo apt update
sudo apt-get install libsgx-epid libsgx-urts libsgx-launch libsgx-quote-ex

#or

# METHOD 2: Installer
#make psw_install_pkg
#sudo chmod +x ./linux/installer/bin/sgx_linux_x64_psw_$SDK_VERSION.bin
#cp ./linux/installer/bin/sgx_linux_x64_psw_$SDK_VERSION.bin /opt
#sudo ../linux/installer/bin/sgx_linux_x64_psw_$SDK_VERSION.bin

#or

# METHOD 3: Manual 
#mkdir /opt/psw
#cp $(find . -name "*.deb") /opt/psw

#sudo dpkg -i /opt/psw/libsgx-headers_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-quote-ex_$SDK_VERSION-jammy1_amd64.deb    
#sudo dpkg -i /opt/psw/libsgx-quote-ex-dev_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-enclave-common_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-enclave-common-dev_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-urts_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-ae-pce_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-pce-logic_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-epid_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-epid-dev_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-launch_$SDK_VERSION-jammy1_amd64.deb 
#sudo dpkg -i /opt/psw/libsgx-launch-dev_$SDK_VERSION-jammy1_amd64.deb  
#sudo dpkg -i /opt/psw/sgx-aesm-service_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-ae-epid_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-aesm-pce-plugin_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-aesm-epid-plugin_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-uae-service_$SDK_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-ae-le_$SDK_VERSION-jammy1_amd64.deb 
#sudo dpkg -i /opt/psw/libsgx-aesm-launch-plugin_$SDK_VERSION-jammy1_amd64.deb    

# Enter

# --- DCAP 
#sudo dpkg -i /opt/psw/libsgx-ae-id-enclave_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-ae-qe3_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-ae-qve_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-qe3-logic_$PSW_VERSION-jammy1_amd64.deb   
#sudo dpkg -i /opt/psw/libsgx-ae-tdqe_$PSW_VERSION-jammy1_amd64.deb    
#sudo dpkg -i /opt/psw/libtdx-attest_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libtdx-attest-dev_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-ra-network_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-ra-uefi_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-ra-uefi-dev_$PSW_VERSION-jammy1_amd64.deb      
#sudo dpkg -i /opt/psw/libsgx-aesm-ecdsa-plugin_$SDK_VERSION-jammy1_amd64.deb     
#sudo dpkg -i /opt/psw/libsgx-aesm-quote-ex-plugin_$SDK_VERSION-jammy1_amd64.deb  
#sudo dpkg -i /opt/psw/libsgx-tdx-logic_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-tdx-logic-dev_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/sgx-pck-id-retrieval-tool_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/sgx-ra-service_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/tdx-qgs_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-dcap-ql_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-dcap-quote-verify-dev_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-dcap-quote-verify_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-dcap-default-qpl_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/libsgx-dcap-default-qpl-dev_$PSW_VERSION-jammy1_amd64.deb
#sudo dpkg -i /opt/psw/sgx-dcap-pccs_$PSW_VERSION-jammy1_amd64.deb

# NOTE: for DCAP we should install libsgx-dcap-ql instead
# NOTE: for DCAP we should install libsgx-quote-ex instead
 

# ----- Gramine
echo "deb http://deb.debian.org/debian $(lsb_release -sc)-backports main" \
| sudo tee /etc/apt/sources.list.d/backports.list

sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
| sudo tee /etc/apt/sources.list.d/gramine.list

sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" \
| sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update
sudo apt-get install gramine -y
is-sgx-available
gramine-sgx-gen-private-key
sudo cp -r ~/.config /root/

# ----- Python Substrate Interface
sudo apt install python3-pip -y
pip install --upgrade pip
pip install "scalecodec>=1.1.2"
pip install substrate-interface
pip install base58

# ----- cosign
# wget https://github.com/sigstore/cosign/releases/download/v2.1.1/cosign_2.1.1_amd64.deb
# sudo dpkg -i cosign_2.1.1_amd64.deb

# ----- Ternoa
# cd /opt
# git clone https://github.com/capsule-corp-ternoa/sgx_server.git
# cd sgx_server

# NOTE: On new DOMAIN, gramine/certificates will be invalid, you'll need to remove them before start
# NOTE: For production, please be careful about certs, never delete them, because every domain has 5 times quota every week.
# NOTE: It takes 20 seconds for sgx_server to start, that's because of fetch new certificates.

# --dev         builds and signs the binary everytime, so you need to provide password for signing with cosign private-key.
# --release     downloads binary and signature from Ternoa github repository
# --domain      is critical for certificates of tls/https 
# --port        different enclaves on the same machine need to have different ports

# sudo CHAIN="mainnet" ./scripts/start-server.sh --domain dev-c1n1.ternoa.network --port 8100  --dev

# You can test the server on the specific DOMAIN and PORT with
# curl -s https://mainnet-c1n1.ternoa.network:8100/api/health | jq .

# You can stop the server on the specific PORT and clean intermediate files with :
# sudo scripts/stop-server.sh --port 8100

# Resume the server without clearing previous files
# sudo CHAIN="mainnet" ./scripts/resume-server.sh --domain dev-c1n1.ternoa.network --port 8100 --dev
