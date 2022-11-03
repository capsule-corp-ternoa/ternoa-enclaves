echo "Get block hash based on block number"
curl --cacert ./credentials/certificates/ssl_certs/ca_bundle.crt -X GET https://ns5019429.ip-15-235-119.net:3000/api/rpcQuery/1112

echo "Get nft data based on nft_id"
curl --cacert ./credentials/certificates/ssl_certs/ca_bundle.crt -X GET https://ns5019429.ip-15-235-119.net:3000/api/getNFTData/4321

echo "Transfer specified amount of CAPS from Alice to Bob"
curl --cacert ./credentials/certificates/ssl_certs/ca_bundle.crt -X GET [/https://ns5019429.ip-15-235-119.net:3000/api/submitTx/14983760328739

echo "Send secret shares to TEE"
curl --cacert ./credentials/certificates/ssl_certs/ca_bundle.crt -X POST https://ns5019429.ip-15-235-119.net:3000/api/nft/storeSecretShares -H 'Content-Type: application/json' -d '{"account_address":"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET","secret_data":{"nft_id": 48384, "data": [84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 104, 97, 114, 101, 32, 111, 102, 32, 53, 32, 115, 104, 97, 114, 101, 115, 33]}, "signature": "b470dd2191c15df731e7fd38b416bc4024f8203702b5218fb8b30cd5fc8e1d0493651435e19339dddcef8e4c247d7a92f831405d8acb435405a11170b7360380"}'

echo "Get secret shares from TEE"
curl --cacert ./credentials/certificates/ssl_certs/ca_bundle.crt -X POST https://ns5019429.ip-15-235-119.net:3000/api/nft/retrieveSecretShares -H 'Content-Type: application/json' -d '{"account_address":"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET","secret_data":{"nft_id": 48384, "data": [0, 1, 2, 3, 4, 5, 6, 7]}, "signature": "889530b69f4aa0280c85db8175ff86e1a4f49bf71396bc829775e9866598bf65147f2e1aef5e870f13c2a47af40ff58f6483ec730595b7b11c6bf4401e851a82"}'
