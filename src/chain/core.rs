#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::upper_case_acronyms)]

use axum::{extract::Path as PathExtract, response::IntoResponse};
use futures::future::join_all;
use serde::Serialize;

use sp_core::H256;
use std::fmt;
use subxt::{
	storage::address::{Address, StaticStorageMapKey, Yes},
	tx::PairSigner,
	tx::Signer,
	utils::AccountId32,
	Error, OnlineClient, PolkadotConfig,
};

use tracing::{debug, error, info};

#[cfg_attr(
	feature = "mainnet",
	subxt::subxt(runtime_metadata_path = "./credentials/artifacts/ternoa_mainnet.scale")
)]
#[cfg_attr(
	feature = "alphanet",
	subxt::subxt(runtime_metadata_path = "./credentials/artifacts/ternoa_alphanet.scale")
)]
#[cfg_attr(
	feature = "dev-1",
	subxt::subxt(runtime_metadata_path = "./credentials/artifacts/ternoa_dev1.scale")
)]
#[cfg_attr(
	feature = "dev-0",
	subxt::subxt(runtime_metadata_path = "./credentials/artifacts/ternoa_dev0.scale")
)]

pub mod ternoa {}
use crate::servers::http_server::SharedState;

use self::ternoa::runtime_types::ternoa_pallets_primitives::nfts::NFTData;
pub type DefaultApi = OnlineClient<PolkadotConfig>;

#[derive(Serialize)]
pub enum ReturnStatus {
	RETRIEVESUCCESS,
	NFTNOTFOUND,
	BLOCKNOTFOUND,
}

// -------------- CHAIN API --------------

/// Creates a new chain API
/// # Returns
/// * `DefaultApi` - The chain API
pub async fn create_chain_api() -> Result<DefaultApi, Error> {
	debug!("5-1 get chain API");

	let rpc_endoint = if cfg!(feature = "mainnet") {
		"wss://mainnet.ternoa.network:443".to_string()
	} else if cfg!(feature = "alphanet") {
		"wss://alphanet.ternoa.com:443".to_string()
	} else if cfg!(feature = "dev-1") {
		"wss://dev-1.ternoa.network:443".to_string()
	} else {
		"wss://dev-0.ternoa.network:443".to_string()
	};

	DefaultApi::from_url(rpc_endoint).await
}

/// Get the current block number
/// # Returns
/// * `u32` - The current block number
pub async fn get_chain_api(state: SharedState) -> DefaultApi {
	let shared_state_read = state.read().await;
	shared_state_read.get_rpc_client()
}

// -------------- BLOCK NUMBER --------------

/// Get the current block number
/// # Returns
/// * `u32` - The current block number
pub async fn get_current_block_number(state: SharedState) -> Result<u32, Error> {
	debug!("current_block : get api");
	let api = get_chain_api(state).await;

	debug!("current_block : get block number");
	let last_block = match api.blocks().at_latest().await {
		Ok(last_block) => last_block,
		Err(err) => {
			error!("core : unable to get latest block : {}", err);
			return Err(err);
		},
	};

	Ok(last_block.number())
}

/// Get the current block number by creating new chain API and reading the blockchain
/// # Returns
/// * `u32` - The current block number

pub async fn get_current_block_number_new_api() -> Result<u32, Error> {
	debug!("current_block : get api");

	let api = match create_chain_api().await {
		Ok(api) => api,
		Err(err) => return Err(err),
	};

	debug!("current_block : get finalize head");
	let hash = match api.rpc().finalized_head().await {
		Ok(hash) => hash,
		Err(err) => return Err(err),
	};

	debug!("current_block : get block number");
	let last_block = match api.rpc().block(Some(hash)).await {
		Ok(Some(last_block)) => last_block,
		Ok(None) => {
			return Err(subxt::Error::Io(std::io::Error::new(
				std::io::ErrorKind::Other,
				"Block not found",
			)))
		},
		Err(err) => return Err(err),
	};

	Ok(last_block.block.header.number)
}

// -------------- GET NFT/CAPSULE DATA --------------

/// Get the NFT/Capsule data
/// # Arguments
/// * `nft_id` - The NFT/Capsule ID
pub async fn get_onchain_nft_data(state: SharedState, nft_id: u32) -> Option<NFTData<AccountId32>> {
	debug!("4-1 get chain NFT DATA");
	let api = get_chain_api(state).await;

	let storage_address = ternoa::storage().nft().nfts(nft_id);

	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!("Failed to get storage: {:?}", err);
			return None;
		},
	};

	match storage.fetch(&storage_address).await {
		Ok(nft_data) => nft_data,
		Err(err) => {
			error!("Failed to fetch NFT data: {:?}", err);
			None
		},
	}
}

// -------------- GET DELGATEE --------------

/// Get the NFT/Capsule delegatee
/// # Arguments
/// * `nft_id` - The NFT/Capsule ID
pub async fn get_onchain_delegatee(state: SharedState, nft_id: u32) -> Option<AccountId32> {
	debug!("4-2 get chain API");

	let api = get_chain_api(state).await;

	let storage_address = ternoa::storage().nft().delegated_nf_ts(nft_id);

	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!("Failed to get storage: {:?}", err);
			return None;
		},
	};

	match storage.fetch(&storage_address).await {
		Ok(delegated) => delegated,
		Err(err) => {
			error!("Failed to fetch NFT data: {:?}", err);
			None
		},
	}
}

/// Get the NFT/Capsule rent contract
/// # Arguments
/// * `nft_id` - The NFT/Capsule ID
/// # Returns
/// * `Option<AccountId32>` - The rent contract
pub async fn get_onchain_rent_contract(state: SharedState, nft_id: u32) -> Option<AccountId32> {
	debug!("4-3 get chain API");

	let api = get_chain_api(state).await;

	let storage_address = ternoa::storage().rent().contracts(nft_id);

	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!("Failed to get storage: {:?}", err);
			return None;
		},
	};

	match storage.fetch(&storage_address).await {
		Ok(rent_contract) => match rent_contract {
			Some(data) => data.rentee,
			_ => {
				error!("Failed to fetch NFT data: {:?}", rent_contract);
				None
			},
		},
		Err(err) => {
			error!("Failed to fetch NFT data: {:?}", err);
			None
		},
	}
}

// -------------- BATCH/CONCURRENT --------------

// Concurrent NFT Data

/* TODO : use TAIT (Type Alias Implementation Trait) when rust start supporting it https://blog.rust-lang.org/2022/09/22/Rust-1.64.0.html#whats-in-1640-stable

type NFTDataType = Result<Option<<<AddressType as subxt::storage::StorageAddress>::Target as subxt::metadata::DecodeWithMetadata>::Target>, subxt::Error>;

type StorageAddressRequestFuture = Pin<Box<dyn Future<Output = NFTDataType>>>;

impl IntoFuture for AddressType {
	type IntoFuture = StorageAddressRequestFuture;
	type Output = <StorageAddressRequestFuture as Future>::Output;
	fn into_future(self) -> Self::IntoFuture {
		Box::pin(self.send())
	}
}
*/

/// Get the NFT/Capsule data
/// # Arguments
/// * `nft_ids` - The NFT/Capsule IDs

pub async fn get_nft_data_batch(nft_ids: Vec<u32>) -> Vec<Option<NFTData<AccountId32>>> {
	debug!("4-4 get nft data batch");

	type AddressType = Address<StaticStorageMapKey, NFTData<AccountId32>, Yes, (), Yes>;
	//StaticStorageAddress<DecodeStaticType<NFTData<AccountId32>>, Yes, (), Yes>;

	let api = create_chain_api().await.unwrap();

	let nft_address: Vec<AddressType> =
		nft_ids.iter().map(|id| ternoa::storage().nft().nfts(id)).collect();

	let mut fetches = Vec::new();
	for nft_addr in nft_address.iter().take(nft_ids.len()) {
		// Critical line with complex type
		let nft_data_future = api.storage().at_latest().await.unwrap().fetch(nft_addr);
		fetches.push(nft_data_future);
	}

	let join_result: Vec<Result<Option<NFTData<AccountId32>>, subxt::Error>> =
		join_all(fetches).await;

	join_result.into_iter().map(|jr| jr.unwrap()).collect()
}

#[derive(Serialize)]
struct JsonNFTData {
	status: ReturnStatus,
	nft_id: u32,
	owner: String,
	creator: String,
	offchain_data: String,
}

impl fmt::Display for NFTData<AccountId32> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
            f,
            "owner: {:#?},\n creator: {:#?}\n offchain_data: {:#?},\n royalty: {},\n collection_id: {},\n state: {:#?},\n",
            self.owner,
            self.creator,
            //std::str::from_utf8(&self.offchain_data.0).unwrap(),
	    	self.offchain_data.0,
            self.royalty.0,
            self.collection_id.unwrap_or(0u32),
            self.state
        )
	}
}

// -------------- SECRET-NFT SYNC (ORACLE) --------------

// TODO: Define macro for nft/capsule
// TODO: Proof of storage (through heart-beats)
// TODO: Proof of decryption (i.e This key-share belongs to the key for decrypting the corresponding
// nft media file on IPFS)

/// Add a secret shard to the NFT/Capsule
/// # Arguments
/// * `keypair` - The keypair of the oracle
/// * `nft_id` - The NFT/Capsule ID
/// # Returns
/// * `Result<sp_core::H256, subxt::Error>` - The transaction hash
pub async fn nft_keyshare_oracle(
	state: SharedState,
	keypair: sp_core::sr25519::Pair,
	nft_id: u32,
) -> Result<sp_core::H256, subxt::Error> {
	debug!("4-5 NFT ORACLE");

	let api = get_chain_api(state).await;

	// Submit Extrinsic
	let signer = PairSigner::new(keypair);

	// Create a transaction to submit:
	let tx = ternoa::tx().nft().add_secret_shard(nft_id);

	// With nonce
	api.tx().create_signed(&tx, &signer, Default::default()).await?.submit().await
}

// -------------- CAPSULE SYNC (ORACLE) --------------

// TODO: Define macro for nft/capsule
// TODO: Proof of storage (through heart-beats)
// TODO: Proof of decryption (i.e This key-share belongs to the key for decrypting the corresponding
// nft media file on IPFS)

/// Add a secret shard to the NFT/Capsule
/// # Arguments
/// * `keypair` - The keypair of the oracle
/// * `nft_id` - The NFT/Capsule ID
/// # Returns
/// * `Result<sp_core::H256, subxt::Error>` - The transaction hash
pub async fn capsule_keyshare_oracle(
	state: SharedState,
	keypair: sp_core::sr25519::Pair,
	nft_id: u32,
) -> Result<sp_core::H256, subxt::Error> {
	debug!("4-6 CAPSULE ORACLE");

	let api = get_chain_api(state).await;

	// Submit Extrinsic
	let signer = PairSigner::new(keypair);

	// Create a transaction to submit:
	let tx = ternoa::tx().nft().add_capsule_shard(nft_id);

	// submit the transaction with default params:
	//api.tx().sign_and_submit_default(&tx, &signer).await

	// With nonce
	api.tx().create_signed(&tx, &signer, Default::default()).await?.submit().await
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;
	use rand::{thread_rng, Rng};
	use std::time::Instant;

	pub async fn get_constant() -> impl IntoResponse {
		let api = create_chain_api().await.unwrap();
		// Build a constant address to query:
		let address = ternoa::constants().balances().existential_deposit();
		// Look it up:
		let existential_deposit = api.constants().at(&address).unwrap();
		info!("Existential Deposit: {}", existential_deposit);
	}

	pub async fn storage_query() -> impl IntoResponse {
		let api = create_chain_api().await.unwrap();
		let address = ternoa::storage().system().account_root();

		let mut iter = api.storage().at_latest().await.unwrap().iter(address, 10).await.unwrap();
		let mut counter = 0;
		while let Some((key, account)) = iter.next().await.unwrap() {
			info!("{}: {}", hex::encode(key), account.data.free);
			counter += 1;
			if counter > 10 {
				break;
			}
		}
	}

	#[tokio::test]
	async fn concurrent_nft_test() {
		let mut rng = thread_rng();
		let nft_ids: Vec<u32> = (1..220).map(|_| rng.gen_range(100..11000)).collect();

		// Concurrent (Avg. 0.3 ms/request on dev-0)
		let start = Instant::now();
		let nft_data_vec = get_nft_data_batch(nft_ids.clone()).await;
		let elapsed_time = start.elapsed().as_micros();
		println!("\nConcurrent time is {} microseconds", elapsed_time);
		println!("Concurrent NFT Data : {:#?}", nft_data_vec[9].as_ref().unwrap().owner);
	}
}
