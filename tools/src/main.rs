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
	subxt::subxt(runtime_metadata_path = "../../credentials/artifacts/ternoa_mainnet.scale")
)]
#[cfg_attr(
	feature = "alphanet",
	subxt::subxt(runtime_metadata_path = "../../credentials/artifacts/ternoa_alphanet.scale")
)]
#[cfg_attr(
	feature = "dev-1",
	subxt::subxt(runtime_metadata_path = "../../credentials/artifacts/ternoa_dev1.scale")
)]
#[cfg_attr(
	feature = "dev-0",
	subxt::subxt(runtime_metadata_path = "../../credentials/artifacts/ternoa_dev0.scale")
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
		return Err(Error::Other("Unknown chain".to_string()))
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
		Ok(None) =>
			return Err(subxt::Error::Io(std::io::Error::new(
				std::io::ErrorKind::Other,
				"Block not found",
			))),
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Seed Phrase for Admin or NFT-Owner
	#[arg(short, long, default_value_t = String::new())]
	seed: String,

	/// Version of backup API i.e 0.2.0 , 0.3.0
	#[arg(short, long, default_value_t = String::from("0.3.0"))]
	api_version: String,

	/// Path to (ZIP-) File, containing sealed NFT key-shares backups
	#[arg(short, long, default_value_t = String::new())]
	file: String,

	/// NFT-ID for storing keyshares in enclave
	#[arg(short, long, default_value_t = 0)]
	nftid: u32,
}

/* MAIN */
#[tokio::main]
async fn main() {
	let args = Args::parse();

	if std::path::Path::new(&args.file).exists() {
		generate_push_bulk(args.seed.clone(), args.file).await;
		return
	}
	
	if args.nftid > 0 {
		generate_retrieve_request(args.seed.clone(), args.nftid).await;
		generate_store_request(args.seed, args.nftid).await;
		return
	}

	match args.api_version.as_str() {
		"0.2.0" | "0.1.0" => generate_fetch_bulk_old(args.seed.clone()).await,
		_ => generate_fetch_bulk(args.seed.clone()).await,
	}
	
}

/* ************************
	 ADMIN FETCH BULK
*************************/

async fn generate_fetch_bulk(seed_phrase: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let last_block_number = get_current_block_number().await.unwrap();

	let admin_address = admin.public().to_ss58check();
	let auth = FetchAuthenticationToken { block_number: last_block_number, block_validation: 15};
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
 ADMIN FETCH BULK OLD
*************************/

async fn generate_fetch_bulk_old(seed_phrase: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let last_block_number = get_current_block_number().await.unwrap();

	let admin_address = admin.public().to_ss58check();
	let auth = FetchAuthenticationToken { block_number: last_block_number, block_validation: 15 };
	let signature = admin.sign(&serde_json::to_vec(&auth).unwrap());

	let packet = FetchBulkPacketOld {
		admin_address,
		auth_token: auth,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!("================================== OLD Fetch Bulk Packet = \n{}\n", serde_json::to_string_pretty(&packet).unwrap());
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
		block_validation: 15,
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
	pub data: String, // TODO: Replace by "SecretData" JWT/JWS
	pub signature: String,
}

async fn generate_store_request(seed_phrase: String, nftid: u32) {
	let current_block_number = get_current_block_number().await.unwrap();
	let owner = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let signer = sr25519::Pair::generate().0;

	let signer_address = format!("{}_{}_15", signer.public().to_ss58check(), current_block_number);
	let signersig = owner.sign(signer_address.as_bytes());
	let data = format!(
		"{}_This-Is-My-Secret-Data-Which-Can-not-Contain-Any-UnderScore-(:-P)_{}_15",nftid,
		current_block_number
	);
	let signature = signer.sign(data.as_bytes());

	let packet = StoreKeysharePacket {
		owner_address: owner.public(),
		signer_address,
		signersig: format!("{}{:?}", "0x", signersig),
		data,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!("==================================  Secret Store Request = \n{}\n", serde_json::to_string_pretty(&packet).unwrap());
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
	pub data: String, // TODO: Replace by "SecretData" JWT/JWS
	pub signature: String,
}

async fn generate_retrieve_request(seed_phrase: String, nftid: u32) {
	let current_block_number = get_current_block_number().await.unwrap();
	let owner = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let data = format!("{}_{}_15", nftid, current_block_number);

	let signature = owner.sign(data.as_bytes());

	let packet = RetrieveKeysharePacket {
		requester_address: owner.public(),
		requester_type: RequesterType::OWNER,
		data,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!("==================================  Secret Retrieve Request = \n{}\n", serde_json::to_string_pretty(&packet).unwrap());
}
