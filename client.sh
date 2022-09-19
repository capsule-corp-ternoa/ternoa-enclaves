echo "Get block hash based on block number"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt https://141.94.162.196:3000/api/rpcQuery/1112

echo "Get nft data based on nft_id"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt https://141.94.162.196:3000/api/getNFTData/4321

echo "Transfer specified amount of CAPS from Alice to Bob"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt https://141.94.162.196:3000/api/submitTx/14983760328739

echo "Send secret shares to TEE"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt -X POST https://141.94.162.196:3000/api/nft/storeSecretShares -H 'Content-Type: application/json' -d '{"account_address":"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET","secret_data":[0, 189, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 84, 104, 105, 115, 32, 105, 115, 32, 111, 110, 101, 32, 115, 104, 97, 114, 101, 32, 111, 102, 32, 101, 105, 103, 104, 116, 32, 115, 104, 97, 114, 101, 115, 32, 111, 102, 32, 115, 101, 99, 114, 101, 116, 33], "signature": "de0eb6a2a5409d201f141314517c2f7afe6ee30f1081c57923454fba15462862b43595b9248402a67bbc46505eeae9db3f896c3fcdcceb950c067a7d80a35e83"}'

echo "Get secret shares from TEE"
curl --cacert ./credentials/certificates/ssl_certs/141-94-162-96/ca_bundle.crt -X GET https://141.94.162.196:3000/api/nft/retrieveSecretShares -H 'Content-Type: application/json' -d '{"account_address":"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET","data":[0, 189, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 84, 104, 105, 115, 32, 105, 115, 32, 111, 110, 101, 32, 115, 104, 97, 114, 101, 32, 111, 102, 32, 101, 105, 103, 104, 116, 32, 115, 104, 97, 114, 101, 115, 32, 111, 102, 32, 115, 101, 99, 114, 101, 116, 33], "signature": "de0eb6a2a5409d201f141314517c2f7afe6ee30f1081c57923454fba15462862b43595b9248402a67bbc46505eeae9db3f896c3fcdcceb950c067a7d80a35e83"}'
