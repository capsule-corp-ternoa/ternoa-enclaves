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

PASSWORD="The1Most3Complex0Pass7word-"

rm *.enc *.crt *.csr *.srl *.key *.pem
echo "$PASSWORD" > plainpass

# Encrypt plain-password file 
echo -e "${FgCyan} Encrypt plain-password file ${Reset}"
openssl enc -aes256 -pbkdf2 -salt -in plainpass -out mypass.enc

rm plainpass

# Generate Private Key
echo -e "${FgCyan} Generate Private Key ${Reset}"
openssl genrsa -des3 -passout file:mypass.enc -out ca.key 4096

# OpenSSL verify Private Key content
echo -e "${Bright} OpenSSL verify Private Key content ${Reset}"
openssl rsa -noout -text -in ca.key -passin file:mypass.enc

# Create Certificate Authority Certificate
echo -e "${FgCyan} Create Certificate Authority Certificate ${Reset}"
openssl req -new -x509 -days 365 -key ca.key -out ca.cert.pem -passin file:mypass.enc

# OpenSSL verify CA certificate
echo -e "${Bright} OpenSSL verify CA certificate ${Reset}"
openssl x509 -noout -text -in ca.cert.pem

# Generate a server key and request for signing (CSR)
echo -e "${FgCyan} Generate a server key and request for signing (CSR) ${Reset}"
openssl genrsa -des3 -passout file:mypass.enc -out server.key 4096
openssl req -new -key server.key -out server.csr -passin file:mypass.enc

# OpenSSL verify server key content
echo -e "${Bright}  OpenSSL verify server key content ${Reset}"
openssl rsa -noout -text -in server.key -passin file:mypass.enc

# OpenSSL verify Certificate Signing Request (CSR)
echo -e "${Bright} OpenSSL verify Certificate Signing Request (CSR) ${Reset}"
openssl req -noout -text -in server.csr

# Sign a certificate with CA
echo -e "${FgCyan} Sign a certificate with CA ${Reset}"
openssl x509 -req -days 365 -in server.csr -CA ca.cert.pem -CAkey ca.key -CAcreateserial -out server.crt -passin file:mypass.enc

# OpenSSL verify server certificate
echo -e "${Bright}  OpenSSL verify server certificate ${Reset}"
openssl x509 -noout -text -in server.crt

# To Remove the pass-phrase
# openssl rsa -in server.key -out server.key.insecure -passin file:mypass.enc

echo -e "${FgBlue}  Generate pem files ${Reset}"
openssl rsa -in server.key -text -passin file:mypass.enc > private.pem
openssl x509 -inform PEM -in server.crt > public.pem
