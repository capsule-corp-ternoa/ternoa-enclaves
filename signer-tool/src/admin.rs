use std::io::Read;

use serde::{Deserialize, Serialize};

use subxt::ext::sp_core::{crypto::Ss58Codec, sr25519, Pair};

use crate::helper;

/* *************************************
		FETCH BULK DATA STRUCTURES
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
	admin_account: String,
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
		STORE BULK DATA STRUCTURES
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
	admin_account: String,
	restore_file: Vec<u8>,
	auth_token: StoreAuthenticationToken,
	signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct FetchBulkPacketOld {
	admin_account: String,
	auth_token: FetchAuthenticationToken,
	signature: String,
}

/* *************************************
		ADMIN ID DATA STRUCTURES
**************************************** */

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IdAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
	pub data_hash: String,
}

/// Fetch NFTID Data
#[derive(Serialize, Deserialize, Debug)]
pub struct IdPacket {
	admin_account: String,
	id_vec: String,
	auth_token: String,
	signature: String,
}

/* ************************
	 ADMIN FETCH BULK
*************************/

pub async fn generate_fetch_bulk(seed_phrase: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let current_block_number = helper::get_current_block_number().await.unwrap();

	let admin_account = admin.public().to_ss58check();
	let auth =
		FetchAuthenticationToken { block_number: current_block_number, block_validation: 10 };
	let auth_str = serde_json::to_string(&auth).unwrap();
	let signature = admin.sign(auth_str.as_bytes());

	let packet = FetchBulkPacket {
		admin_account,
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
pub async fn generate_push_bulk(seed_phrase: String, file_path: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let current_block_number = helper::get_current_block_number().await.unwrap();

	//let admin_account = admin.public().to_ss58check();

	let mut zipdata = Vec::new();
	let mut zipfile = std::fs::File::open(&file_path).unwrap();
	let _ = zipfile.read_to_end(&mut zipdata).unwrap();

	let hash = sha256::digest(zipdata.as_slice());

	let auth = StoreAuthenticationToken {
		block_number: current_block_number,
		block_validation: 10,
		data_hash: hash,
	};

	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = admin.sign(auth_str.as_bytes());
	let sig_str = format!("{}{:?}", "0x", sig);

	println!(
		"================================== Push Bulk Packet = \n Admin:\t\t {} \n Auth_Token:\t {} \n Signature:\t {} \n ",
		admin.public(),
		auth_str,
		sig_str
	);
}

/* ************************
	 ADMIN FETCH ID
*************************/

pub async fn generate_fetch_id(seed_phrase: String, id_vec: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let current_block_number = helper::get_current_block_number().await.unwrap();

	let admin_account = admin.public().to_ss58check();
	let hash = sha256::digest(id_vec.as_bytes());
	let auth = IdAuthenticationToken {
		block_number: current_block_number,
		block_validation: 10,
		data_hash: hash,
	};
	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = admin.sign(auth_str.as_bytes());
	let signature = format!("0x{:?}", sig);

	let packet = IdPacket { admin_account, id_vec, auth_token: auth_str, signature };

	println!(
		"================================== Backup Fetch ID Packet = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

/* ************************
	 ADMIN PUSH ID
*************************/
pub async fn generate_push_id(seed_phrase: String, id_vec: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let block_number = helper::get_current_block_number().await.unwrap();

	let admin_account = admin.public().to_ss58check();

	let data_hash = sha256::digest(id_vec.as_bytes());

	let auth = IdAuthenticationToken { block_number, block_validation: 10, data_hash };

	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = admin.sign(auth_str.as_bytes());
	let signature = format!("0x{:?}", sig);

	let packet = IdPacket { admin_account, id_vec, auth_token: auth_str, signature };

	println!(
		"================================== Backup Push ID Packet = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}
