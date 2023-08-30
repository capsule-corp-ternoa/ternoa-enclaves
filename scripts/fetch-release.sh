AUTHTOKEN=
VERSION_TAG=

if [ "$1" ]; then
    AUTHTOKEN=$1
else
    read -p "Github Authentication Token :" AUTHTOKEN
fi

if [ "$2" ]; then
    VERSION_TAG=$2
else
    read -p "Binary Version/Tag :" VERSION_TAG
fi

CURL="curl -H 'X-GitHub-Api-Version: 2022-11-28' -H 'Accept: application/vnd.github+json' -H 'Authorization: token $AUTHTOKEN' https://api.github.com/repos/capsule-corp-ternoa/sgx_server/releases"

#       TAGS
CURL_BINARY_ID="$CURL/tags/$VERSION_TAG"
BINARY=$(eval $CURL_BINARY_ID | jq .assets[0].id)

CURL_SIGNATURE_ID="$CURL/tags/$VERSION_TAG"
SIGNATURE=$(eval $CURL_SIGNATURE_ID | jq .assets[1].id)

#       ASSETS
EVAL_BINARY="$CURL/assets/$BINARY -LJOH 'Accept: application/octet-stream'"
eval $EVAL_BINARY

EVAL_SIGNATURE="$CURL/assets/$SIGNATURE -LJOH 'Accept: application/octet-stream'"
eval $EVAL_SIGNATURE
