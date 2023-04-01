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
use subxt::{tx::PairSigner, utils::AccountId32, OnlineClient, PolkadotConfig, Error};

#[cfg_attr(
	feature = "mainnet",
	subxt::subxt(runtime_metadata_path = "../../../credentials/artifacts/ternoa_mainnet.scale")
)]
#[cfg_attr(
	feature = "alphanet",
	subxt::subxt(runtime_metadata_path = "../../../credentials/artifacts/ternoa_alphanet.scale")
)]
#[cfg_attr(
	feature = "dev-1",
	subxt::subxt(runtime_metadata_path = "../../../credentials/artifacts/ternoa_dev1.scale")
)]
#[cfg_attr(
	feature = "dev-0",
	subxt::subxt(runtime_metadata_path = "../../../credentials/artifacts/ternoa_dev0.scale")
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
	} else if cfg!(feature = "alphanetnet") {
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
		Ok(None) => return Err(subxt::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "Block not found"))),
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
	/// Path to the location for storing sealed NFT key-shares
	#[arg(short, long)]
	seed: String,

	#[arg(short, long)]
	file: String,
}

/* MAIN */
#[tokio::main]
async fn main() {
    let args = Args::parse();
    generate_fetch_bulk(args.seed.clone()).await;
    generate_fetch_bulk_old(args.seed.clone()).await;
	generate_push_bulk(args.seed, args.file).await;
}


async fn generate_fetch_bulk(seed_phrase: String) {
    let admin = sr25519::Pair::from_phrase(
        &seed_phrase,
        None,
    )
    .unwrap()
    .0;

    let last_block_number = get_current_block_number().await.unwrap();

    let admin_address = admin.public().to_ss58check();
    let auth =
        FetchAuthenticationToken { block_number: last_block_number, block_validation: 10 };
    let auth_str = serde_json::to_string(&auth).unwrap();
    let signature = admin.sign(auth_str.as_bytes());

    let packet = FetchBulkPacket {
        admin_address,
        auth_token: auth_str, 
        signature: format!("{}{:?}", "0x", signature),
    };

    println!("***** NEW Fetch Bulk Packet = \n{}\n", serde_json::to_string_pretty(&packet).unwrap());
}


async fn generate_fetch_bulk_old(seed_phrase: String) {
    let admin = sr25519::Pair::from_phrase(
        &seed_phrase,
        None,
    )
    .unwrap()
    .0;

    let last_block_number = get_current_block_number().await.unwrap();

    let admin_address = admin.public().to_ss58check();
    let auth =
        FetchAuthenticationToken { block_number: last_block_number, block_validation: 10 };
    let signature = admin.sign(&serde_json::to_vec(&auth).unwrap());

    let packet = FetchBulkPacketOld {
        admin_address,
        auth_token: auth, 
        signature: format!("{}{:?}", "0x", signature),
    };

    println!("***** OLD Fetch Bulk Packet = \n{}\n", serde_json::to_string(&packet).unwrap());
}

async fn generate_push_bulk(seed_phrase: String, file_path: String) {
	let admin = sr25519::Pair::from_phrase(
        &seed_phrase,
        None,
    )
    .unwrap()
    .0;

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
		"***** Push Bulk Packet = \n Admin:\t\t {} \n Auth_Token:\t {} \n Signature:\t {} \n ",
		admin.public(),
		auth_str,
		sig_str
	);
}