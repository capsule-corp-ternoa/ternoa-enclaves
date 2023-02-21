
### ENCLAVE HEALTH-CHECK
echo "Health check"
curl  https://dev-c1n1.ternoa.network:8101/api//health

### SECRET-NFT
echo "Get NFT views log"
curl  https://dev-c1n1.ternoa.network:8101/api//secret-nft/get-views-log/494

echo "Get NFT key-share availability on enclave"
curl  https://dev-c1n1.ternoa.network:8101/api//secret-nft/is-keyshare-available/494

echo "Store NFT key-hares to TEE"
curl -X POST https://dev-c1n1.ternoa.network:8101/api//secret-nft/store-keyshare -H 'Content-Type: application/json' -d '{  "owner_address": "5CcqaTBwWvbB2MvmeteSDLVujL3oaFHtdf24pPVT3Xf8v7tC",  "signer_address": "5G1AGcU2D8832LcRefKrPm8Zrob63vf6uQSzKGmhyV9DrzFs_214299_1000000",  "signersig": "0xa6f4b9fcb96291c3b9a628449ace134e161f0aa7f7b6b1c7bfb42a3398919038dfa104362fdda1cb5954838909cd7dff08f8bd2d49b097d11fd3b7d14b6c9682",  "secret_data": "494_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_214299_1000000",  "signature": "0xd2ae8f5d20214212a94bb55bfd88d748eaabbbffeec0b372811f78b60279de512c44ca87720703b20de52a50595f4551b8b13e538dffd3ac18968d8412dba98d"}'

echo "Get NFT key-shares from TEE"
curl -X POST https://dev-c1n1.ternoa.network:8101/api//secret-nft/retrieve-keyshare -H 'Content-Type: application/json' -d '{  "owner_address": "5CcqaTBwWvbB2MvmeteSDLVujL3oaFHtdf24pPVT3Xf8v7tC",  "data": "494_214299_1000000",  "signature": "0x22d8812c669c67b98bcba386528fe80e17452d9a1c55871305d61f1c85a1210648860309ce280225dec32eb3b9f82382df30f581328a32f2a7d6f44ae422e48c"}'

echo "Remove NFT key-shares from TEE"
curl -X POST https://dev-c1n1.ternoa.network:8101/api//secret-nft/remove-keyshare -H 'Content-Type: application/json' -d '{  "owner_address": "5G1AGcU2D8832LcRefKrPm8Zrob63vf6uQSzKGmhyV9DrzFs",  "nft_id": 494}'

### CAPSULE
echo "Get CAPSULE views log"
curl  https://dev-c1n1.ternoa.network:8101/api//capsule-nft/get-views-log/494

echo "Get CAPSULE key-share availability on enclave"
curl  https://dev-c1n1.ternoa.network:8101/api//capsule-nft/is-keyshare-available/494

echo "Set CAPSULE key-hares to TEE"
curl -X POST https://dev-c1n1.ternoa.network:8101/api//capsule-nft/set-keyshare -H 'Content-Type: application/json' -d '{  "owner_address": "5CcqaTBwWvbB2MvmeteSDLVujL3oaFHtdf24pPVT3Xf8v7tC",  "signer_address": "5G1AGcU2D8832LcRefKrPm8Zrob63vf6uQSzKGmhyV9DrzFs_214299_1000000",  "signersig": "0xa6f4b9fcb96291c3b9a628449ace134e161f0aa7f7b6b1c7bfb42a3398919038dfa104362fdda1cb5954838909cd7dff08f8bd2d49b097d11fd3b7d14b6c9682",  "secret_data": "494_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_214299_1000000",  "signature": "0xd2ae8f5d20214212a94bb55bfd88d748eaabbbffeec0b372811f78b60279de512c44ca87720703b20de52a50595f4551b8b13e538dffd3ac18968d8412dba98d"}'

echo "Get CAPSULE key-shares from TEE"
curl -X POST https://dev-c1n1.ternoa.network:8101/api//capsule-nft/retrieve-keyshare -H 'Content-Type: application/json' -d '{  "owner_address": "5CcqaTBwWvbB2MvmeteSDLVujL3oaFHtdf24pPVT3Xf8v7tC",  "data": "494_214299_1000000",  "signature": "0x22d8812c669c67b98bcba386528fe80e17452d9a1c55871305d61f1c85a1210648860309ce280225dec32eb3b9f82382df30f581328a32f2a7d6f44ae422e48c"}'

echo "Remove CAPSULE key-shares from TEE"
curl -X POST https://dev-c1n1.ternoa.network:8101/api//capsule-nft/remove-keyshare -H 'Content-Type: application/json' -d '{  "owner_address": "5G1AGcU2D8832LcRefKrPm8Zrob63vf6uQSzKGmhyV9DrzFs",  "nft_id": 494}'
