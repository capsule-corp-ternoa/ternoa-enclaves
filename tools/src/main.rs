#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use clap::Parser;
use hex::{FromHex, FromHexError};
use serde_json::{json, Value};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};

use std::{
	collections::BTreeMap,
	io::{Read, Write},
};

use std::fs::{remove_file, File};
use tracing::{debug, error, info, warn};

use serde::{Deserialize, Serialize};
use sp_core::{crypto::PublicError, sr25519::Signature};
use subxt::{tx::PairSigner, utils::AccountId32, Error, OnlineClient, PolkadotConfig};

#[cfg_attr(
	feature = "mainnet",
	subxt::subxt(runtime_metadata_path = "../credentials/artifacts/ternoa_mainnet.scale")
)]
#[cfg_attr(
	feature = "alphanet",
	subxt::subxt(runtime_metadata_path = "../credentials/artifacts/ternoa_alphanet.scale")
)]
#[cfg_attr(
	feature = "dev-1",
	subxt::subxt(runtime_metadata_path = "../credentials/artifacts/ternoa_dev1.scale")
)]
#[cfg_attr(
	feature = "dev-0",
	subxt::subxt(runtime_metadata_path = "../credentials/artifacts/ternoa_dev0.scale")
)]

pub mod ternoa {}
use self::ternoa::runtime_types::ternoa_pallets_primitives::nfts::NFTData;
type DefaultApi = OnlineClient<PolkadotConfig>;

// -------------- CHAIN API --------------
/// Get the chain API
/// # Returns
/// * `DefaultApi` - The chain API
pub async fn get_chain_api() -> Result<DefaultApi, Error> {
	debug!("5-1 get chain API");

	let rpc_endoint = if cfg!(feature = "mainnet") {
		"wss://mainnet.ternoa.network:443".to_string()
	} else if cfg!(feature = "alphanet") {
		"wss://alphanet.ternoa.com:443".to_string()
	} else if cfg!(feature = "dev-1") {
		"wss://dev-1.ternoa.network:443".to_string()
	} else if cfg!(feature = "dev-0") {
		"wss://dev-0.ternoa.network:443".to_string()
	} else {
		return Err(Error::Other("Unknown chain".to_string()));
	};

	println!("endpoint  = {rpc_endoint}\n");

	DefaultApi::from_url(rpc_endoint).await
}

/// Get the current block number
/// # Returns
/// * `u32` - The current block number
pub async fn get_current_block_number() -> Result<u32, Error> {
	let api = match get_chain_api().await {
		Ok(api) => api,
		Err(err) => return Err(err),
	};

	let hash = match api.rpc().finalized_head().await {
		Ok(hash) => hash,
		Err(err) => return Err(err),
	};

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

/* *************************************
		FETCH  BULK DATA STRUCTURES
**************************************** */

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FetchAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
}

/// Fetch Bulk Data
#[derive(Serialize, Deserialize)]
pub struct FetchBulkPacket {
	admin_address: String,
	auth_token: String, //FetchAuthenticationToken,
	signature: String,
}

/// Fetch Bulk Response
#[derive(Serialize)]
pub struct FetchBulkResponse {
	data: String,
	signature: String,
}

/* *************************************
		STORE  BULK DATA STRUCTURES
**************************************** */

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StoreAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
	pub data_hash: String,
}

/// Store Bulk Packet
#[derive(Serialize, Deserialize)]
pub struct StoreBulkPacket {
	admin_address: String,
	restore_file: Vec<u8>,
	auth_token: StoreAuthenticationToken,
	signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct FetchBulkPacketOld {
	admin_address: String,
	auth_token: FetchAuthenticationToken,
	signature: String,
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Request type : [retrieve, store] for secrets [fetch, restore] for backup
	#[arg(short, long, default_value_t = String::new())]
	request: String,

	/// Seed Phrase for Admin or NFT-Owner
	#[arg(short, long, default_value_t = String::new())]
	seed: String,

	/// Path to (ZIP-) File, containing sealed NFT key-shares backups
	#[arg(short, long, default_value_t = String::new())]
	file: String,

	/// NFTID of the secret to be stored or retrived, If 'Custom-Data' option is present, this option will be ignored
	#[arg(short, long, default_value_t = 0)]
	nftid: u32,

	/// Secret_data for storing keyshares in enclave
	#[arg(short, long, default_value_t = String::new())]
	secret_share: String,

	/// BlockNumber (Optional)
	#[arg(short, long, default_value_t = 0)]
	block_number: u32,

	/// Number of blocks after the current block number which after it, the request is invalid. (Optional)
	#[arg(short, long, default_value_t = 15)]
	expire: u8,

	/// Custom Data, right format is "NFTID_SecretShare_CurrentBlockNumber_Expire"
	#[arg(short, long, default_value_t = String::new())]
	custom_data: String,
}

/* MAIN */
#[tokio::main]
async fn main() {
	let args = Args::parse();

	if args.seed.is_empty() {
		println!("\n Seed-phrase can not be empty! \n");
		return;
	}

	if args.nftid > 0 || !args.custom_data.is_empty() {
		match args.request.to_lowercase().as_str() {
			"retrieve" => generate_retrieve_request(args.clone()).await,
			"store" => generate_store_request(args).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	}else if std::path::Path::new(&args.file).exists() {
		match args.request.to_lowercase().as_str() {
			"restore" => generate_push_bulk(args.seed.clone(), args.file).await,
			"fetch" => generate_fetch_bulk(args.seed.clone()).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	}else {
		println!("\n Please provide either a NFTID or a Custom Data \n");
		return;
	}
}

/* ************************
	 ADMIN FETCH BULK
*************************/

async fn generate_fetch_bulk(seed_phrase: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let last_block_number = get_current_block_number().await.unwrap();

	let admin_address = admin.public().to_ss58check();
	let auth = FetchAuthenticationToken { block_number: last_block_number, block_validation: 10 };
	let auth_str = serde_json::to_string(&auth).unwrap();
	let signature = admin.sign(auth_str.as_bytes());

	let packet = FetchBulkPacket {
		admin_address,
		auth_token: auth_str,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!(
		"================================== Backup Fetch Bulk Packet = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

/* ************************
	 ADMIN PUSH BULK
*************************/
async fn generate_push_bulk(seed_phrase: String, file_path: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let last_block_number = get_current_block_number().await.unwrap();

	let admin_address = admin.public().to_ss58check();

	let mut zipdata = Vec::new();
	let mut zipfile = std::fs::File::open(&file_path).unwrap();
	let _ = zipfile.read_to_end(&mut zipdata).unwrap();

	let hash = sha256::digest(zipdata.as_slice());

	let auth = StoreAuthenticationToken {
		block_number: last_block_number,
		block_validation: 10,
		data_hash: hash,
	};

	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = admin.sign(auth_str.as_bytes());
	let sig_str = format!("{}{:?}", "0x", sig);

	println!(
		"==================================  Push Bulk Packet = \n Admin:\t\t {} \n Auth_Token:\t {} \n Signature:\t {} \n ",
		admin.public(),
		auth_str,
		sig_str
	);
}

/* ************************
   SECRET STORE REQUEST
*************************/
// Validity time of Keyshare Data
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
}

// Keyshare Data structure
#[derive(Clone, Debug, PartialEq)]
pub struct StoreKeyshareData {
	pub nft_id: u32,
	pub keyshare: Vec<u8>,
	pub auth_token: AuthenticationToken,
}

// Packet-signer and validity of it
#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct Signer {
	account: sr25519::Public,
	auth_token: AuthenticationToken,
}

#[derive(Serialize, Clone)]
pub struct StoreKeysharePacket {
	pub owner_address: sr25519::Public,

	// Signed by owner
	signer_address: String,
	signersig: String,

	// Signed by signer
	pub data: String,
	pub signature: String,
}

async fn generate_store_request(args: Args) {

	let owner = sr25519::Pair::from_phrase(&args.seed, None).unwrap().0;
	let signer = sr25519::Pair::generate().0;

	let current_block_number = if args.block_number > 0 {
		args.block_number
	} else {
		get_current_block_number().await.unwrap()
	};

	let signer_address =
		format!("{}_{}_{}", signer.public().to_ss58check(), current_block_number, args.expire);
	let signersig = owner.sign(signer_address.as_bytes());

	let secret_share = if !args.secret_share.is_empty() {
		args.secret_share
	}else {
		"This-is-a-Sample-Secret!@#$%^&*()1234567890".to_string()
	};

	let data = if !args.custom_data.is_empty() {
		args.custom_data
	} else {
		format!(
			"{}_{}_{}_{}",
			args.nftid, secret_share, current_block_number, args.expire
		)
	};

	let signature = signer.sign(data.as_bytes());

	let packet = StoreKeysharePacket {
		owner_address: owner.public(),
		signer_address,
		signersig: format!("{}{:?}", "0x", signersig),
		data,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!(
		"\n==================================  Secret Store Request = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

#[derive(Serialize, Debug, Clone, Copy)]
pub enum RequesterType {
	OWNER,
	DELEGATEE,
	RENTEE,
	NONE,
}

#[derive(Serialize, Clone)]
pub struct RetrieveKeysharePacket {
	pub requester_address: sr25519::Public,
	pub requester_type: RequesterType,
	pub data: String,
	pub signature: String,
}

async fn generate_retrieve_request(args: Args) {
	if args.nftid == 0 && args.custom_data.is_empty() {
		println!("\n NFTID is unknown! \n");
		return;
	}

	let current_block_number = get_current_block_number().await.unwrap();
	let owner = sr25519::Pair::from_phrase(&args.seed, None).unwrap().0;

	let data = if !args.custom_data.is_empty() {
		args.custom_data
	} else {
		format!("{}_{}_{}", args.nftid, current_block_number, args.expire)
	};

	let signature = owner.sign(data.as_bytes());

	let packet = RetrieveKeysharePacket {
		requester_address: owner.public(),
		requester_type: RequesterType::OWNER,
		data,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!(
		"\n==================================  Secret Retrieve Request = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}
