use axum::{extract::Path as PathExtract, response::IntoResponse};
use serde::Serialize as SerderSerialize;

use sp_core::H256;
use sp_keyring::AccountKeyring;
use std::fmt;

use subxt::{ext::sp_core::Pair, tx::PairSigner, OnlineClient, PolkadotConfig};

use subxt::ext::sp_runtime::AccountId32;
//use crate::chain::chain::ternoa::runtime_types::sp_core::crypto::AccountId32;
use crate::chain::chain::ternoa::runtime_types::ternoa_pallets_primitives::nfts::NFTData;

const TERNOA_ALPHANET_RPC: &'static str = "wss://alphanet.ternoa.com:443";

#[subxt::subxt(runtime_metadata_path = "./credentials/artifacts/ternoa_alphanet.scale")]
pub mod ternoa {}

type DefaultApi = OnlineClient<PolkadotConfig>;

pub async fn get_chain_api(url: String) -> DefaultApi {
	if url.is_empty() {
		TERNOA_ALPHANET_RPC.to_string()
	} else {
		url
	};
	// Create a client to use:
	let api = DefaultApi::from_url(TERNOA_ALPHANET_RPC).await.unwrap();

	api
}

#[derive(SerderSerialize)]
struct JsonRPC {
	status: u16,
	input: String,
	output: String,
}

pub async fn rpc_query(PathExtract(block_number): PathExtract<u32>) -> impl IntoResponse {
	let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await;
	// RPC : Get Block-Hash
	let block_hash = api.rpc().block_hash(Some(block_number.into())).await.unwrap();

	if let Some(hash) = block_hash {
		println!("Block hash for block number {block_number}: {hash}");
		axum::Json(JsonRPC {
			status: 200,
			input: "block_number=".to_owned() + &block_number.to_string(),
			output: "block_hash=".to_owned() + &block_hash.unwrap().to_string(),
		})
	} else {
		println!("Block number {block_number} not found.");
		axum::Json(JsonRPC {
			status: 205,
			input: "block_number=".to_owned() + &block_number.to_string(),
			output: "Block number not found.".to_string(),
		})
	}
}

pub async fn get_constant() -> impl IntoResponse {
	let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await;
	// Build a constant address to query:
	let address = ternoa::constants().balances().existential_deposit();
	// Look it up:
	let existential_deposit = api.constants().at(&address).unwrap();
	println!("Existential Deposit: {}", existential_deposit);
}

pub async fn storage_query() -> impl IntoResponse {
	let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await;
	let address = ternoa::storage().system().account_root();

	let mut iter = api.storage().iter(address, 10, None).await.unwrap();
	let mut counter = 0;
	while let Some((key, account)) = iter.next().await.unwrap() {
		println!("{}: {}", hex::encode(key), account.data.free);
		counter += 1;
		if counter > 10 {
			break
		}
	}
}

#[derive(SerderSerialize)]
struct JsonTX {
	status: u16,
	amount: u128,
	sender: String,
	receiver: String,
	tx_hash: H256,
}

pub async fn submit_tx(PathExtract(amount): PathExtract<u128>) -> impl IntoResponse {
	let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await;

	// Submit Extrinsic
	let key = subxt::ext::sp_core::sr25519::Pair::from_string("//TernoaTestAccount", None).unwrap();
	let signer = PairSigner::new(key);
	let dest = AccountKeyring::Alice.to_account_id().into();

	// Create a transaction to submit:
	let tx = ternoa::tx().balances().transfer(dest, amount);

	// submit the transaction with default params:
	let hash = api.tx().sign_and_submit_default(&tx, &signer).await.unwrap();

	println!("Balance transfer extrinsic submitted: {}", hash);

	axum::Json(JsonTX {
		status: 200,
		amount,
		sender: String::from("//TernoaTestAccount"),
		receiver: String::from("Alice"),
		tx_hash: hash,
	})
}

// -------------- NFTData --------------

pub async fn get_nft_data(nft_id: u32) -> Option<NFTData<AccountId32>> {
	let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await;
	let storage_address = ternoa::storage().nft().nfts(nft_id);
	let result = api.storage().fetch(&storage_address, None).await.unwrap();

	result
}

#[derive(SerderSerialize)]
struct JsonNFTData {
	status: u16,
	nft_id: u32,
	owner: String,
	creator: String,
	offchain_data: String,
}

pub async fn get_nft_data_handler(PathExtract(nft_id): PathExtract<u32>) -> impl IntoResponse {
	let data = get_nft_data(nft_id).await;
	match data {
		Some(nft_data) => {
			println!("NFT DATA of Num.{} : \n {}", nft_id, nft_data);

			axum::Json(JsonNFTData {
				status: 200,
				nft_id,
				owner: nft_data.owner.clone().to_string(),
				creator: nft_data.creator.clone().to_string(),
				offchain_data: String::from_utf8(nft_data.offchain_data.0).unwrap(),
			})
		},
		None => axum::Json(JsonNFTData {
			status: 303,
			nft_id,
			owner: String::from("Not Found"),
			creator: String::from("Not Found"),
			offchain_data: String::from("Not Found"),
		}),
	}
}

impl fmt::Display for NFTData<AccountId32> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
            f,
            "owner: {:#?},\n creator: {:#?}\n offchain_data: {:#?},\n royalty: {},\n collection_id: {},\n state: {:#?},\n",
            self.owner,
            self.creator,
            std::str::from_utf8(&self.offchain_data.0).unwrap(),
            self.royalty.0,
            self.collection_id.unwrap_or(0u32),
            self.state
        )
	}
}

/* ---------------- Tests ---------------- */

#[cfg(test)]
mod test {
	use super::*;

	#[tokio::test]
	async fn static_test() {
		rpc_query(axum::extract::Path(1436090)).await;
		get_constant().await;
		storage_query().await;
		submit_tx(axum::extract::Path(1_4560_7890_0120_3450)).await;
	}

	#[tokio::test]
	async fn nft_test() {
		let nft_data = get_nft_data(29582).await;
		println!("{:#?}", nft_data);
	}
}
