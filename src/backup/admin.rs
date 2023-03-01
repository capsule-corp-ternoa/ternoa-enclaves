use axum::{extract::State, response::IntoResponse, Json};

use hex::{FromHex, FromHexError};
use serde_json::json;
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::{
	collections::BTreeMap,
	io::{Read, Write},
};

use serde::{Deserialize, Serialize};
use sp_core::{crypto::PublicError, sr25519::Signature};

use crate::{
	chain::{chain::get_current_block_number},
	servers::http_server::StateConfig,
};

use super::zipdir::{add_dir_zip, zip_extract};

use tracing::{debug, info};

const BACKUP_WHITELIST: [&str; 2] = [
	"5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy", // Dave
	"5G1AGcU2D8832LcRefKrPm8Zrob63vf6uQSzKGmhyV9DrzFs", // Test
];

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
}

/* ----------------------------------
AUTHENTICATION TOKEN IMPLEMENTATION
----------------------------------*/

// Retrieving the stored Keyshare
impl AuthenticationToken {
	pub async fn is_valid(self) -> bool {
		let last_block_number = get_current_block_number().await;
		(last_block_number > self.block_number - 3) // for finalization delay
			&& (last_block_number < self.block_number + self.block_validation + 3)
	}
}

/* *************************************
		 VERIFICATIONFUNCTIONS
**************************************** */

fn verify_account_id(account_id: &str) -> bool {
	BACKUP_WHITELIST.contains(&account_id)
}

fn get_public_key(account_id: &str) -> Result<sr25519::Public, PublicError> {
	let pk: Result<sr25519::Public, PublicError> = sr25519::Public::from_ss58check(account_id)
		.map_err(|err: PublicError| {
			debug!("Error constructing public key {:?}", err);
			err
		});

	pk
}

/// Returns Signature or else a HexError
fn get_signature(signature: String) -> Result<Signature, FromHexError> {
	let stripped = match signature.strip_prefix("0x") {
		Some(sig) => sig,
		None => signature.as_str(),
	};

	
	match <[u8; 64]>::from_hex(stripped) {
		Ok(s) => {
			let sig = sr25519::Signature::from_raw(s);
			debug!("Signature :- {:?}", sig);
			Ok(sig)
		},
		Err(err) => Err(err),
	}
}

/// Verify Signature generated for a payload
fn verify_signature(account_id: &str, signature: String, message: &[u8]) -> bool {
	match get_public_key(account_id) {
		Ok(pk) => match get_signature(signature) {
			Ok(val) => sr25519::Pair::verify(&val, message, &pk),
			Err(err) => {
				debug!("Error generating pair {:?}", err);
				false
			},
		},
		Err(_) => false,
	}
}

/* *************************************
		 BULK DATA STRUCTURES
**************************************** */

#[derive(Serialize, Deserialize)]
pub struct FetchBulkPacket {
	admin_address: String,
	auth_token: AuthenticationToken,
	signature: String,
}

#[derive(Serialize)]
pub struct FetchBulkResponse {
	data: String,
	signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreBulkData {
	auth_token: AuthenticationToken,
	data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct StoreBulkPacket {
	admin_address: String,
	data: StoreBulkData,
	signature: String,
}

/* *************************************
 BULK RETRIEVE THEKEYSHARES FROM ENCLAVE
**************************************** */
#[axum::debug_handler]
pub async fn backup_fetch_bulk(
	State(state): State<StateConfig>,
	Json(backup_request): Json<FetchBulkPacket>,
) -> impl IntoResponse {
	debug!("3-15 API : backup fetch bulk");

	if !verify_account_id(&backup_request.admin_address) {
		info!("Error backup keyshares : Invalid admin : {}", backup_request.admin_address);

		return Json(json! ({
			"status": "Error backup keyshares : Invalid admin",
			"data": [],
		}))
	}

	if verify_signature(
		&backup_request.admin_address,
		backup_request.signature.clone(),
		&serde_json::to_vec(&backup_request.auth_token).unwrap(),
	) {
		if backup_request.auth_token.is_valid().await {
			let backup_file = state.seal_path.to_owned() + "backup.zip";
			add_dir_zip(&state.seal_path.clone(), &backup_file);

			let mut file = std::fs::File::open(backup_file.clone()).unwrap(); // TODO : manage unwrap
			let mut data = Vec::<u8>::new();
			file.read_to_end(&mut data).unwrap(); // TODO : manage unwrap

			std::fs::remove_file(backup_file).unwrap();

			// TODO : manage big packet transfer
			Json(json! ({
				"status": "Successfull request",
				"data": data,
			}))
		} else {
			Json(json! ({
				"status": "Authentication Token Expired",
				"data": [],
			}))
		}
	} else {
		Json(json! ({
			"status": "Invalid signature",
			"data": [],
		}))
	}
}

/* ******************************
 BULK PUSH KEYSHARES TO THIS ENCLAVE
********************************* */
#[axum::debug_handler]
pub async fn backup_push_bulk(
	State(state): State<StateConfig>,
	Json(store_request): Json<StoreBulkPacket>,
) -> impl IntoResponse {
	debug!("3-16 API : backup push bulk");

	if !verify_account_id(&store_request.admin_address.clone()) {
		info!("Error restore backup keyshares : Invalid admin : {}", store_request.admin_address);

		return Json(json! ({
			"status": "Error restore backup keyshares : Invalid admin",
		}))
	}

	let data = store_request.data.clone();
	let data_bytes = serde_json::to_vec(&data).unwrap();

	if verify_signature(&store_request.admin_address, store_request.signature.clone(), &data_bytes)
	{
		if store_request.data.auth_token.is_valid().await {
			let backup_file = state.seal_path.to_owned() + "backup.zip";

			let mut zipfile = std::fs::File::open(backup_file.clone()).unwrap();
			zipfile.write_all(&data_bytes).unwrap();

			zip_extract(&backup_file, &state.seal_path);

			std::fs::remove_file(backup_file).unwrap();

			// TODO : manage big packet transfer
			Json(json! ({
				"status": "Successfull request",
			}))
		} else {
			Json(json! ({
				"status": "Authentication Token Expired",
				"data": [],
			}))
		}
	} else {
		Json(json! ({
			"status": "Invalid signature",
			"data": [],
		}))
	}
}

/* ******************************
	REQUEST DATA STRUCTURES
****************************** */

#[derive(Debug)]
pub enum BackupError {
	UnAuthorizedSigner,
	InvalidSignature,
}

// -------- Backup -------
#[derive(Serialize, Deserialize, Clone)]
pub struct BackupRequestData {
	nfts: Vec<String>,
	signer_address: String,
}

#[derive(Deserialize, Clone)]
pub struct BackupRequest {
	data: BackupRequestData,
	signature: String,
}

#[derive(Serialize)]
pub struct BackupResponse {
	status: String,
	data: BTreeMap<String, [String; 2]>,
}

// -------- Store -------

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct StoreRequestData {
	nfts: BTreeMap<String, [String; 2]>,
	signer_address: String,
}

#[derive(Deserialize, Clone, PartialEq)]
pub struct StoreRequest {
	data: StoreRequestData,
	signature: String,
}

#[derive(Serialize)]
pub struct StoreResponse {
	status: String,
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;
	
	

	#[tokio::test]
	async fn bulk_fetch_test() {
		let admin_keypair = sr25519::Pair::from_phrase(
			"hockey fine lawn number explain bench twenty blue range cover egg sibling",
			None,
		)
		.unwrap()
		.0;

		let auth = AuthenticationToken { block_number: 300000, block_validation: 1000000 };
		let auth_bytes = serde_json::to_vec(&auth).unwrap();
		let sig = admin_keypair.sign(&auth_bytes);
		let sig_str = serde_json::to_string(&sig).unwrap();

		let _request = FetchBulkPacket {
			admin_address: admin_keypair.public().to_string(),
			auth_token: auth,
			signature: sig_str,
		};
	}

	#[tokio::test]
	async fn bulk_restore_test() {
		let admin_keypair = sr25519::Pair::from_phrase(
			"hockey fine lawn number explain bench twenty blue range cover egg sibling",
			None,
		)
		.unwrap()
		.0;

		let zipdata = "fake_zip_data".as_bytes();
		let auth = AuthenticationToken { block_number: 300000, block_validation: 1000000 };
		let data = StoreBulkData { auth_token: auth.clone(), data: zipdata.to_vec() };
		let auth_str = serde_json::to_vec(&auth).unwrap();
		let sig = admin_keypair.sign(&auth_str);
		let sig_str = serde_json::to_string(&sig).unwrap();

		let _request = StoreBulkPacket {
			admin_address: admin_keypair.public().to_string(),
			data,
			signature: sig_str,
		};
	}

	#[tokio::test]
	async fn fetch_bulk_test() {
		let admin = sr25519::Pair::from_phrase(
			"steel announce garden guilt direct give morning gadget milk census poem faith",
			None,
		)
		.unwrap()
		.0;

		let admin_address = admin.public().to_ss58check();
		let auth = AuthenticationToken { block_number: 1000, block_validation: 10000000 };
		let auth_str = serde_json::to_string(&auth).unwrap();
		let signature = admin.sign(auth_str.as_bytes());

		let packet = FetchBulkPacket {
			admin_address,
			auth_token: auth,
			signature: format!("{}{:?}", "0x", signature),
		};

		println!("FetchBulkPacket = {}\n", serde_json::to_string_pretty(&packet).unwrap());
	}

	#[test]
	fn test_get_signature_valid() {
		let input  = "0xb7255023814e304b72bc880cc993d5c654ce060db0c3f0772b453714c760521962943747af605a90d0503812c6a62c5c1080cbf377095551af0c168a8c724da8".to_string();
		let expected = Signature(<[u8; 64]>::from_hex(input.strip_prefix("0x").unwrap()).unwrap());
		let results = get_signature(input).unwrap();
		assert_eq!(results, expected);
	}

	#[test]
	fn test_get_public_key_valid() {
		let account = "5DAENKLsmj9FbfxgKuWn81smhKz9dZg75fveUFSUtqrr4CPn";
		let results = get_public_key(account).unwrap();
		assert_eq!(results, sp_core::sr25519::Public::from_ss58check(account).unwrap());
	}
}
