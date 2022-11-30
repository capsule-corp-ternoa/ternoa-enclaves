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

PASSWORD="The1Most3Complex0Pass7word!"
echo "$PASSWORD" > plainpass

# Encrypt plain-password file 
echo -e "${FgCyan} Encrypt plain-password file ${Reset}"
openssl enc -aes256 -pbkdf2 -salt -in plainpass -out mypass.enc

# Decrypt
# PASS=123456
#openssl enc -d -aes256 -pbkdf2  -in mypass.enc -out plainpass

# Generate Private Key
echo -e "${FgCyan} Generate Private Key ${Reset}"
openssl genrsa -des3 -passout file:plainpass -out ca.key 4096

# OpenSSL verify Private Key content
echo -e "${Bright} OpenSSL verify Private Key content ${Reset}"
openssl rsa -noout -text -in ca.key -passin file:plainpass

# Create Certificate Authority Certificate
echo -e "${FgCyan} Create Certificate Authority Certificate ${Reset}"
openssl req -new -x509 -days 365 -key ca.key -out ca_cert.pem -passin file:plainpass

# OpenSSL verify CA certificate
echo -e "${Bright} OpenSSL verify CA certificate ${Reset}"
openssl x509 -noout -text -in ca_cert.pem

# Generate a server key and request for signing (CSR)
echo -e "${FgCyan} Generate a server key and request for signing (CSR) ${Reset}"
openssl genrsa -des3 -passout file:plainpass -out server.key 4096
openssl req -new -key server.key -out server.csr -passin file:plainpass

# OpenSSL verify server key content
echo -e "${Bright}  OpenSSL verify server key content ${Reset}"
openssl rsa -noout -text -in server.key -passin file:plainpass

# OpenSSL verify Certificate Signing Request (CSR)
echo -e "${Bright} OpenSSL verify Certificate Signing Request (CSR) ${Reset}"
openssl req -noout -text -in server.csr

# Sign a certificate with CA
echo -e "${FgCyan} Sign a certificate with CA ${Reset}"
openssl x509 -req -days 365 -in server.csr -CA ca_cert.pem -CAkey ca_cert.key -CAcreateserial -out server.crt -passin file:plainpass

# OpenSSL verify server certificate
echo -e "${Bright}  OpenSSL verify server certificate ${Reset}"
openssl x509 -noout -text -in server.crt

# To Remove the pass-phrase
# openssl rsa -in server.key -out server.key.insecure -passin file:plainpass

echo -e "${FgBlue}  Generate pem files ${Reset}"
openssl rsa -in server.key -text -passin file:plainpass > server_key.pem
openssl x509 -inform PEM -in server.crt > server_cert.pem

#rm plainpass
cat server_cert.pem ca_cert.pem > ca_bundle.pem
