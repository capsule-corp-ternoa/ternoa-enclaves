echo "Get block hash based on block number"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt -X GET https://141.94.162.196:3000/api/rpcQuery/1112

echo "Get nft data based on nft_id"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt -X GET https://141.94.162.196:3000/api/getNFTData/4321

echo "Transfer specified amount of CAPS from Alice to Bob"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt -X GET [/https://141.94.162.196:3000/api/submitTx/14983760328739

echo "Send secret shares to TEE"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt -X POST https://141.94.162.196:3000/api/nft/storeSecretShares -H 'Content-Type: application/json' -d '{"account_address":"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET","secret_data":{"nft_id": 48384, "data": "This is a share of 5 shares!"}, "signature": "b470dd2191c15df731e7fd38b416bc4024f8203702b5218fb8b30cd5fc8e1d0493651435e19339dddcef8e4c247d7a92f831405d8acb435405a11170b7360380"}'

echo "Get secret shares from TEE"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt -X POST https://141.94.162.196:3000/api/nft/retrieveSecretShares -H 'Content-Type: application/json' -d '{"account_address":"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET","secret_data":{"nft_id": 48384, "data": "Some description!"}, "signature": "b6f4080e24cba8b4e81236742c15d1c0e592ca5ee8e6f994580394b507046073216ecbd62c21e33b652fc464b6d6a85bfd8ba01e91b0bfa252bcbe1477d2ee8a"}'
