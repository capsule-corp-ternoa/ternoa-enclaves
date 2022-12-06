Reset='\e[0m'
Bright='\e[1m'
Blink='\e[5m'
Reverse='\e[7m'

FgRed='\e[1;31m'
FgGreen='\e[1;32m'
FgBlue='\e[1;34m'
FgCyan='\e[1;36m'

BgBlack='\e[40m'
BgWhite='\e[47m'


touch index.txt
echo 20221200 > serial

# Generate Private Key
echo -e "${FgCyan} Generate Private Key ${Reset}"
openssl ecparam -name secp256r1 -out ./ca_key.pem  -genkey

# Create Certificate Authority Certificate
echo -e "${FgCyan} Create Certificate Authority Certificate ${Reset}"
openssl req -new -x509 -days 3650  -key ./ca_key.pem -out ./ca_cert.pem

# Generate a server key and request for signing (CSR)
echo -e "${FgCyan} Generate a server key and request for signing (CSR) ${Reset}"
openssl ecparam -out ./server_key.pem -name secp384r1 -genkey
openssl req -config ./openssl_server.cnf -new -key ./server_key.pem -out ./server.csr -sha256

# Sign a certificate with CA
echo -e "${FgCyan} Sign a certificate with CA ${Reset}"
openssl ca -config ./openssl_server.cnf -extensions server_cert -days 365 -keyfile ca_key.pem -cert ./ca_cert.pem -in ./server.csr -out ./server_cert.pem

#echo -e "${FgBlue}  Generate pem files ${Reset}"
#openssl ecparam -in ./server.key -text > ./server_key.pem
#openssl x509 -inform PEM -in ./server.crt > ./server_cert.pem

#rm plainpass
cat ./server_cert.pem ./ca_cert.pem > ./ca_bundle.pem
