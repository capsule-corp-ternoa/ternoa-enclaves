AUTHTOKEN=
if [ "$1" ]; then
AUTHTOKEN=$1
else
read -p "Please enter your github authentication-token to access private repository : " AUTHTOKEN
fi

CURL="curl -H 'Authorization: token $AUTHTOKEN' https://api.github.com/repos/capsule-corp-ternoa/sgx_server/releases"

BINARY=$(eval "$CURL/tags/master" | jq .assets[0].id)
SIGNATURE=$(eval "$CURL/tags/master" | jq .assets[1].id)
    
eval "$CURL/assets/$BINARY -LJOH 'Accept: application/octet-stream'"
eval "$CURL/assets/$SIGNATURE -LJOH 'Accept: application/octet-stream'"
