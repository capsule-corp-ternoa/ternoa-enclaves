#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::upper_case_acronyms)]

use axum::{extract::Path as PathExtract, response::IntoResponse};
use futures::future::join_all;
use hex::ToHex;
use serde::Serialize;

use crate::constants::{ALPHANET_GENESIS_HASH, MAINNET_GENESIS_HASH};

//use jsonrpsee_ws_client;
//use jsonrpsee_ws_client::WsClientBuilder;

use std::fmt;
use subxt::{
	backend::{
		legacy::LegacyRpcMethods,
		rpc::{
			reconnecting_rpc_client::{Client, ExponentialBackoff},
			RpcClient,
		},
	},
	config::polkadot::PolkadotExtrinsicParamsBuilder,
	ext::sp_core::H256,
	storage::{StaticAddress, StaticStorageKey},
	tx::{PairSigner, Signer, TxStatus},
	utils::{AccountId32, Yes},
	Error, OnlineClient, PolkadotConfig,
};

use tracing::{debug, error, info, trace};

#[cfg_attr(
	feature = "mainnet",
	subxt::subxt(runtime_metadata_path = "./artifacts/ternoa_mainnet.scale")
)]
#[cfg_attr(
	feature = "alphanet",
	subxt::subxt(runtime_metadata_path = "./artifacts/ternoa_alphanet.scale")
)]
#[cfg_attr(
	feature = "betanet",
	subxt::subxt(runtime_metadata_path = "./artifacts/ternoa_betanet.scale")
)]
#[cfg_attr(feature = "dev1", subxt::subxt(runtime_metadata_path = "./artifacts/ternoa_dev1.scale"))]
#[cfg_attr(feature = "dev0", subxt::subxt(runtime_metadata_path = "./artifacts/ternoa_dev0.scale"))]

pub mod ternoa {}
use crate::server::state::*;

use self::ternoa::{
	nft::storage::types::nfts::Param0, runtime_types::ternoa_pallets_primitives::nfts::NFTData,
};

pub type DefaultApi = OnlineClient<PolkadotConfig>;
pub type ApiRpc = (OnlineClient<PolkadotConfig>, LegacyRpcMethods<PolkadotConfig>);

const RETRY_COUNT: u8 = 3;
const RETRY_DELAY: u64 = 3;

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
pub async fn create_chain_api(rpc_endoint: String) -> Result<ApiRpc, Error> {
	debug!("CHAIN : get chain API");

	let reconnectable_rpc = Client::builder()
		// Reconnect with exponential backoff
		//
		// This API is "iterator-like" and we use `take` to limit the number of retries.
		.retry_policy(
			ExponentialBackoff::from_millis(100)
				.max_delay(std::time::Duration::from_secs(10))
				.take(3),
		)
		// There are other configurations as well that can be found at
		// [`reconnecting_rpc_client::ClientBuilder`].
		.build(rpc_endoint.clone())
		.await?;

	// Chain API
	//let api = match DefaultApi::from_url(rpc_endoint.clone()).await {
	let api: OnlineClient<PolkadotConfig> =
		match OnlineClient::from_rpc_client(reconnectable_rpc.clone()).await {
			Ok(reconnectable_api) => {
				info!("CHAIN : Successfully created chain api.");
				reconnectable_api
			},
			Err(err) => {
				error!("CHAIN : Error acquiring chain api, {:?}", err);
				sentry::capture_error(&err);
				return Err(err);
			},
		};

	// Check Genesis Hash
	let genesis_hash = hex::encode(api.genesis_hash());

	if cfg!(feature = "mainnet") && genesis_hash.as_str() == MAINNET_GENESIS_HASH {
		info!("CHAIN : API : Valid mainnet endpoint");
	}
	else if cfg!(feature = "alphanet") && genesis_hash.as_str() == ALPHANET_GENESIS_HASH {
		info!("CHAIN : API : Valid alphanet endpoint");
	}
	else if cfg!(feature = "alphanet") || cfg!(feature = "mainnet") {
		let error_message = "CHAIN : Error : Genesis Hash mismatch";
		error!(name: "Chain Genesis Mismatch",error_message);
		sentry::capture_message(error_message, sentry::protocol::Level::Error);
		return Err(error_message.into());
	}

	// Legacy RPC
	let rpc_client = RpcClient::from_url(rpc_endoint.clone()).await?;
	let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client.clone());
	//let api = OnlineClient::<PolkadotConfig>::from_rpc_client(rpc_client.clone()).await?;

	Ok((api, legacy_rpc))
}

// -------------- BLOCK NUMBER --------------

/// Get the current block number
/// # Returns
/// * `u32` - The current block number
pub async fn get_current_block_number(state: &SharedState) -> Result<u32, Error> {
	debug!("CHAIN : current_block : get api");
	let (api, _) = get_chain_api(state).await;

	debug!("CHAIN : get current block number");

	let last_block = match api.blocks().at_latest().await {
		Ok(last_block) => last_block,
		Err(err) => {
			error!("CHAIN : unable to get latest block : {}", err);
			set_chain_api_renew(state, true).await;
			sentry::capture_error(&err);
			return Err(err);
		},
	};

	Ok(last_block.number())
}

/// Get the current block number by creating new chain API and reading the blockchain
/// Used for unit testing which does not need SharedState
/// # Returns
/// * `u32` - The current block number

pub async fn get_current_block_number_test() -> Result<u32, Error> {
	debug!("CHAIN : current_block : get api");
	
	let rpcnode = if cfg!(feature = "mainnet") {
		"wss://mainnet.ternoa.io:443".to_string()
	} else if cfg!(feature = "alphanet") {
		"wss://alphanet.ternoa.com:443".to_string()
	} else if cfg!(feature = "betanet") {
		"wss://betanet.ternoa.com:443".to_string()
	} else if cfg!(feature = "dev1") {
		"wss://dev-1.ternoa.network:443".to_string()
	} else if cfg!(feature = "dev0") {
		"wss://dev-0.ternoa.network:443".to_string()
	} else {
		"ws://localhost:9944".to_string()
	};

	let (api, _) = match create_chain_api(rpcnode).await {
		Ok(api) => api,
		Err(err) => return Err(err),
	};

	let mut blocks_sub = api.blocks().subscribe_finalized().await?;

	// TODO: For each block, print details about the `TransferKeepAlive` transactions we are
	// interested in.
	let block = match blocks_sub.next().await {
		Some(block) => block?,
		None => return Err("CHAIN : ERROR : No Block found".into()),
	};

	Ok(block.header().number)
}

// -------------- GET NFT/CAPSULE DATA --------------

/// Get the NFT/Capsule data
/// # Arguments
/// * `nft_id` - The NFT/Capsule ID
pub async fn get_onchain_nft_data(
	state: &SharedState,
	nft_id: u32,
) -> Option<NFTData<AccountId32>> {
	debug!("CHAIN : get chain NFT DATA");
	let (api, _) = get_chain_api(state).await;

	let storage_address = ternoa::storage().nft().nfts(nft_id);

	// Get storage
	let storage: subxt::storage::Storage<PolkadotConfig, OnlineClient<PolkadotConfig>> =
		match api.storage().at_latest().await {
			Ok(storage) => storage,
			Err(err) => {
				set_chain_api_renew(state, true).await;
				error!("CHAIN : Failed to get nft storage: {err:?}");
				sentry::capture_error(&err);
				return None;
			},
		};

	// Fetch data
	match storage.fetch(&storage_address).await {
		Ok(nft_data) => nft_data,
		Err(err) => {
			error!("CHAIN : Failed to fetch NFT data: {err:?}");
			sentry::capture_error(&err);
			None
		},
	}
}

// -------------- GET DELGATEE --------------

/// Get the NFT/Capsule delegatee
/// # Arguments
/// * `nft_id` - The NFT/Capsule ID
pub async fn get_onchain_delegatee(state: &SharedState, nft_id: u32) -> Option<AccountId32> {
	debug!("CHAIN : Delegate");

	let (api, _) = get_chain_api(state).await;

	let storage_address = ternoa::storage().nft().delegated_nf_ts(nft_id);

	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!("CHAIN : Failed to get storage for delegatee: {err:?}");
			set_chain_api_renew(state, true).await;
			sentry::capture_error(&err);
			return None;
		},
	};

	match storage.fetch(&storage_address).await {
		Ok(delegated) => delegated,
		Err(err) => {
			error!("CHAIN : Failed to fetch NFT data for delegatee : {err:?}");
			set_chain_api_renew(state, true).await;
			sentry::capture_error(&err);
			None
		},
	}
}

/// Get the NFT/Capsule rent contract
/// # Arguments
/// * `nft_id` - The NFT/Capsule ID
/// # Returns
/// * `Option<AccountId32>` - The rent contract
pub async fn get_onchain_rent_contract(state: &SharedState, nft_id: u32) -> Option<AccountId32> {
	debug!("CHAIN : Rent contract");

	let (api, _) = get_chain_api(state).await;

	let storage_address = ternoa::storage().rent().contracts(nft_id);

	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!("CHAIN : Failed to get storage for rentee: {err:?}");
			set_chain_api_renew(state, true).await;
			sentry::capture_error(&err);
			return None;
		},
	};

	match storage.fetch(&storage_address).await {
		Ok(rent_contract) => match rent_contract {
			Some(data) => data.rentee,
			_ => {
				error!("CHAIN : Failed to fetch NFT data for rentee : {:?}", rent_contract);
				sentry::capture_message(
					"CHAIN : Failed to fetch NFT data for rentee",
					sentry::Level::Error,
				);
				None
			},
		},
		Err(err) => {
			error!("CHAIN : Failed to fetch NFT data: {err:?}");
			set_chain_api_renew(state, true).await;
			sentry::capture_error(&err);
			None
		},
	}
}

// -------------- SECRET-NFT SYNC (ORACLE) --------------

// TODO [code style] : Define macro for nft/capsule
// TODO [future metric server] : Proof of storage (through heart-beats)
// TODO [idea - future ZK]: Proof of decryption (i.e This key-share belongs to the key for
// decrypting the corresponding nft media file on IPFS)

/// Add a secret shard to the NFT/Capsule
/// # Arguments
/// * `keypair` - The keypair of the oracle
/// * `nft_id` - The NFT/Capsule ID
/// # Returns
/// * `Result<sp_core::H256, subxt::Error>` - The transaction hash
pub async fn nft_keyshare_oracle(state: &SharedState, nft_id: u32) -> Result<H256, subxt::Error> {
	debug!("CHAIN : NFT ORACLE");

	let (api, _) = get_chain_api(state).await;

	// Create a transaction to submit:
	let tx = ternoa::tx().nft().add_secret_shard(nft_id);

	// With nonce
	//let onchain_nonce = api.rpc().system_account_next_index(&signer.account_id()).await?;

	let offchain_nonce = get_nonce(state).await;
	debug!("CHAIN : Secret-NFT Oracle : nonce = {:?}", offchain_nonce);

	{
		increment_nonce(state).await;
		debug!("CHAIN : Secret-nft Oracle : nonce incremented for next extrinsic");
	}

	// Enclave as the Signer
	let shared_state_read = state.read().await;
	let signer = shared_state_read.get_signer();

	let tx_params = PolkadotExtrinsicParamsBuilder::new()
		//.tip(1_000)
		//.mortal(api.blocks().at_latest().await?.header(), 32)
		.nonce(offchain_nonce)
		.build();

	// Create the extrinsic
	let mut tx_submit_watch = api
		.tx()
		.sign_and_submit_then_watch(&tx, signer, tx_params)
		// It is better to submit and watch, is it compatible with nonce and multiple extrinsics?
		.await?;

	// Replacement of wait_for_in_block() in Subxt version 33
	while let Some(status) = tx_submit_watch.next().await {
		match status? {
			TxStatus::InBestBlock(tx_in_block) | TxStatus::InFinalizedBlock(tx_in_block) => {
				// now, we can attempt to work with the block, eg:
				let extrinsic_hash = tx_in_block.wait_for_success().await?.extrinsic_hash();
				debug!("CHAIN : Secret-nft Oracle : extrinsic sent : {:?}", extrinsic_hash);
				return Ok(extrinsic_hash);
			},
			TxStatus::Error { message } |
			TxStatus::Invalid { message } |
			TxStatus::Dropped { message } => {
				// Handle any errors:
				let error_message = format!("Error submitting tx: {message}");
				error!(error_message);
				return Err(error_message.into());
			},
			// Continue otherwise:
			_ => continue,
		}
	}

	Err("CHAIN : Error : Secret-nft Oracle failed".into())
}

// -------------- CAPSULE SYNC (ORACLE) --------------

/// Add a secret shard to the NFT/Capsule
/// # Arguments
/// * `keypair` - The keypair of the oracle
/// * `nft_id` - The NFT/Capsule ID
/// # Returns
/// * `Result<sp_core::H256, subxt::Error>` - The transaction hash
pub async fn capsule_keyshare_oracle(
	state: &SharedState,
	nft_id: u32,
) -> Result<H256, subxt::Error> {
	debug!("CHAIN : CAPSULE ORACLE");

	let (api, _) = get_chain_api(state).await;

	// Create a transaction to submit:
	let tx = ternoa::tx().nft().add_capsule_shard(nft_id);

	// With nonce
	//let onchain_nonce = api.rpc().system_account_next_index(&signer.account_id()).await?;

	let offchain_nonce = get_nonce(state).await;
	debug!("CHAIN : Capsule Oracle : nonce = {:?}", offchain_nonce);

	{
		increment_nonce(state).await;
		debug!("CHAIN : Capsule Oracle : nonce incremented for next extrinsic");
	}

	// Enclave as the Signer
	let shared_state_read = state.read().await;
	let signer = shared_state_read.get_signer();

	let tx_params = PolkadotExtrinsicParamsBuilder::new()
		//.tip(1_000)
		//.mortal(api.blocks().at_latest().await?.header(), 32)
		.nonce(offchain_nonce)
		.build();

	// Create the extrinsic
	let mut tx_submit_watch = api
		.tx()
		.sign_and_submit_then_watch(&tx, signer, tx_params)
		// It is better to submit and watch, is it compatible with nonce and multiple extrinsics?
		.await?;

	// Replacement of wait_for_in_block() in Subxt version 33
	while let Some(status) = tx_submit_watch.next().await {
		match status? {
			TxStatus::InBestBlock(tx_in_block) | TxStatus::InFinalizedBlock(tx_in_block) => {
				// now, we can attempt to work with the block, eg:
				let extrinsic_hash = tx_in_block.wait_for_success().await?.extrinsic_hash();
				debug!("CHAIN : Capsule Oracle : extrinsic sent : {:?}", extrinsic_hash);
				return Ok(extrinsic_hash);
			},
			TxStatus::Error { message } |
			TxStatus::Invalid { message } |
			TxStatus::Dropped { message } => {
				// Handle any errors:
				let error_message = format!("Error submitting tx: {message}");
				error!(error_message);
				return Err(error_message.into());
			},
			// Continue otherwise:
			_ => continue,
		}
	}

	Err("CHAIN : Error : Capsule Oracle failed ".into())
}

/// Get Metric Server
/// # Arguments
/// * `nft_id` - The NFT/Capsule ID
/// # Returns
/// * `Option<AccountId32>` - The rent contract
pub type MetricServer =
	ternoa::runtime_types::ternoa_tee::types::MetricsServer<subxt::utils::AccountId32>;
pub async fn get_metric_server(state: &SharedState) -> Option<Vec<MetricServer>> {
	debug!("CHAIN : GET METRIC SERVER");

	let (api, _) = get_chain_api(state).await;

	let storage_address = ternoa::storage().tee().metrics_servers();

	// Get storage
	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!(
				"CHAIN : GET METRIC SERVER : Failed to get storage for metric server : {:?}",
				err
			);
			set_chain_api_renew(state, true).await;
			sentry::capture_error(&err);
			return None;
		},
	};

	// Fetch
	match storage.fetch(&storage_address).await {
		Ok(metric_servers) => match metric_servers {
			Some(bv) => return Some(bv.0),
			_ => {
				error!(
					"CHAIN : GET METRIC SERVER : Failed to parse metric server vector : {:?}",
					metric_servers
				);
				set_chain_api_renew(state, true).await;
				sentry::capture_message(
					"CHAIN : GET METRIC SERVER : Failed to parse metric server vector",
					sentry::Level::Error,
				);
				return None;
			},
		},

		Err(err) => {
			error!("CHAIN : GET METRIC SERVER : Failed to fetch metric servers : {:?}", err);
			set_chain_api_renew(state, true).await;
			sentry::capture_error(&err);
		},
	}

	None
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
		write!(f, "owner: {:#?},\n creator: {:#?}\n offchain_data: {:#?},\n royalty: {},\n collection_id: {},\n state: {:#?},\n",
 				self.owner,
 				self.creator,
 				//std::str::from_utf8(&self.offchain_data.0).unwrap(),
	 			self.offchain_data.0,
 				self.royalty.0,
 				self.collection_id.unwrap_or(0u32),
 				self.state)
	}
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
		let rpcnode = if cfg!(feature = "mainnet") {
			"wss://mainnet.ternoa.io:443".to_string()
		} else if cfg!(feature = "alphanet") {
			"wss://alphanet.ternoa.com:443".to_string()
		} else if cfg!(feature = "betanet") {
			"wss://betanet.ternoa.com:443".to_string()
		} else if cfg!(feature = "dev1") {
			"wss://dev-1.ternoa.network:443".to_string()
		} else if cfg!(feature = "dev0") {
			"wss://dev-0.ternoa.network:443".to_string()
		} else {
			"ws://localhost:9944".to_string()
		};

		let (api, _) = create_chain_api(rpcnode).await.unwrap();
		// Build a constant address to query:
		let address = ternoa::constants().balances().existential_deposit();
		// Look it up:
		let existential_deposit = api.constants().at(&address).unwrap();
		info!("Existential Deposit: {}", existential_deposit);
	}

	pub async fn storage_query() -> impl IntoResponse {
		let rpcnode = if cfg!(feature = "mainnet") {
			"wss://mainnet.ternoa.io:443".to_string()
		} else if cfg!(feature = "alphanet") {
			"wss://alphanet.ternoa.com:443".to_string()
		} else if cfg!(feature = "betanet") {
			"wss://betanet.ternoa.com:443".to_string()
		} else if cfg!(feature = "dev1") {
			"wss://dev-1.ternoa.network:443".to_string()
		} else if cfg!(feature = "dev0") {
			"wss://dev-0.ternoa.network:443".to_string()
		} else {
			"ws://localhost:9944".to_string()
		};

		let (api, _) = create_chain_api(rpcnode).await.unwrap();
		let address = ternoa::storage().system().account_iter();

		let mut iter = api.storage().at_latest().await.unwrap().iter(address).await.unwrap();
		let mut counter = 0;
		while let Ok(kv) = iter.next().await.unwrap() {
			info!("{}: {}", hex::encode(kv.key_bytes), kv.value.data.free);
			counter += 1;
			if counter > 10 {
				break;
			}
		}
	}
}
