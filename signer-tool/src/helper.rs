use clap::Parser;
use hex::{FromHex, FromHexError};

use subxt::{
	backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
	ext::sp_core::{
		crypto::{PublicError, Ss58Codec},
		sr25519::{self, Signature},
		Pair,
	},
	Error, OnlineClient, PolkadotConfig,
};

use tracing::debug;

#[cfg_attr(
	feature = "mainnet",
	subxt::subxt(runtime_metadata_path = "../artifacts/ternoa_mainnet.scale")
)]
#[cfg_attr(
	feature = "alphanet",
	subxt::subxt(runtime_metadata_path = "../artifacts/ternoa_alphanet.scale")
)]
#[cfg_attr(
	feature = "dev1",
	subxt::subxt(runtime_metadata_path = "../artifacts/ternoa_dev1.scale")
)]
#[cfg_attr(
	feature = "dev0",
	subxt::subxt(runtime_metadata_path = "../artifacts/ternoa_dev0.scale")
)]

pub mod ternoa {}
//use self::ternoa::runtime_types::ternoa_pallets_primitives::nfts::NFTData;
pub type DefaultApi = OnlineClient<PolkadotConfig>;
pub type ApiRpc = (OnlineClient<PolkadotConfig>, LegacyRpcMethods<PolkadotConfig>);

/* *************************************
			INPUT ARGUMENTS
**************************************** */

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
	/// Request type : [retrieve, store] for secrets
	/// Request type : [fetch-bulk, push-bulk, fetch-id, push-id] for backup
	/// Request type : [reconcilliation] for metrics
	/// Request type : [attest] for remote attestation
	#[arg(short, long, default_value_t = String::new())]
	pub request: String,

	/// Seed Phrase for Admin or NFT-Owner
	#[arg(short, long, default_value_t = String::new())]
	pub seed: String,

	/// Path to (ZIP-) File, containing sealed NFT key-shares backups
	#[arg(short, long, default_value_t = String::new())]
	pub file: String,

	/// NFTID of the secret to be stored or retrived, If 'Custom-Data' option is present, this
	/// option will be ignored
	#[arg(short, long, default_value_t = 0)]
	pub nftid: u32,

	/// NFTID Vector of the secret to be fetched or pushed by admin
	#[arg(short, long, default_value_t = String::new())]
	pub id_vec: String,

	/// Block-Number Interval as a Vector to check the nft-ids in that interval
	#[arg(short, long, default_value_t = String::new())]
	pub block_interval: String,

	/// Path to (ZIP-) File, containing sealed NFT key-shares backups
	#[arg(short, long, default_value_t = String::new())]
	pub quote: String,

	/// Secret_data for storing keyshares in enclave
	#[arg(long, default_value_t = String::new())]
	pub secret_share: String,

	/// BlockNumber (Optional)
	#[arg(short, long, default_value_t = 0)]
	pub block_number: u32,

	/// Number of blocks after the current block number which after it, the request is invalid.
	/// (Optional)
	#[arg(short, long, default_value_t = 15)]
	pub expire: u8,

	/// Custom Data, right format is "NFTID_SecretShare_CurrentBlockNumber_Expire"
	#[arg(short, long, default_value_t = String::new())]
	pub custom_data: String,

	/// Enclave URL, right format is "https://enclave.address"
	#[arg(short, long, default_value_t = String::new())]
	pub enclave_url: String,
}

// -------------- CHAIN API --------------
/// Get the chain API
/// # Returns
/// * `DefaultApi` - The chain API

pub async fn get_chain_api() -> Result<ApiRpc, Error> {
	debug!("CHAIN : get chain API");

	let rpc_endoint = if cfg!(feature = "mainnet") {
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

	// Chain API
	let api = DefaultApi::from_url(rpc_endoint.clone()).await?;

	// Legacy RPC
	let rpc_client = RpcClient::from_url(rpc_endoint.clone()).await?;
	let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client.clone());
	//let api = OnlineClient::<PolkadotConfig>::from_rpc_client(rpc_client.clone()).await?;

	Ok((api, legacy_rpc))
}

/// Get the current block number
/// # Returns
/// * `u32` - The current block number
pub async fn get_current_block_number() -> Result<u32, Error> {
	let (api, _) = match get_chain_api().await {
		Ok(al) => al,
		Err(err) => return Err(err),
	};

	let block = match api.blocks().at_latest().await {
		Ok(blk) => blk,
		Err(err) => return Err(err),
	};

	Ok(block.number())
}

fn get_public_key(account_id: &str) -> Result<sr25519::Public, PublicError> {
	let pk: Result<sr25519::Public, PublicError> = sr25519::Public::from_ss58check(account_id)
		.map_err(|err: PublicError| {
			debug!("Error constructing public key {err:?}");
			err
		});

	pk
}

fn get_signature(signature: String) -> Result<Signature, FromHexError> {
	let stripped = match signature.strip_prefix("0x") {
		Some(sig) => sig,
		None => signature.as_str(),
	};

	match <[u8; 64]>::from_hex(stripped) {
		Ok(s) => {
			let sig = sr25519::Signature::from_raw(s);
			Ok(sig)
		},
		Err(err) => Err(err),
	}
}

pub fn verify_signature(account_id: &str, signature: String, message: &[u8]) -> bool {
	match get_public_key(account_id) {
		Ok(pk) => match get_signature(signature) {
			Ok(val) => sr25519::Pair::verify(&val, message, &pk),
			Err(err) => {
				debug!("Error get signature {err:?}");
				false
			},
		},
		Err(_) => {
			debug!("Error get public key from account-id");
			false
		},
	}
}
