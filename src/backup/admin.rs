use axum::{debug_handler, extract::State, http::StatusCode, response::IntoResponse, Json};

use hex::{FromHex, FromHexError};
use serde_json::json;
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::{
	collections::BTreeMap,
	io::{Read, Write},
};

use tracing::info;

use serde::{Deserialize, Serialize};
use sp_core::crypto::PublicError;
use sp_core::ecdsa::Public;
use sp_core::sr25519::Signature;

use crate::{
	chain::{chain::get_current_block_number, log::*},
	servers::http_server::StateConfig,
};

use super::zipdir::{add_dir_zip, zip_extract};

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
	let pk: Result<sr25519::Public, PublicError> = sr25519::Public::from_ss58check(account_id).or_else(|err: PublicError| {
		log::debug!("Error constructing public key {:?}", err);
		Err(err)
	});

	pk
}

/// Returns Signature or else a HexError
fn get_signature(signature: String) -> Result<Signature, FromHexError> {
	let stripped = match signature.strip_prefix("0x") {
		Some(sig) => sig,
		None => signature.as_str(),
	};

	let sb = match <[u8; 64]>::from_hex(stripped) {
		Ok(s) => {
			let sig = sr25519::Signature::from_raw(s);
			Ok(sig)
		}
		Err(err) => Err(err),
	};
	sb
}

/// Verify Signature generated for a payload
fn verify_signature(account_id: &str, signature: String, message: &[u8]) -> bool {
	match get_public_key(account_id) {
		Ok(pk) => match get_signature(signature) {
			Ok(val) => sr25519::Pair::verify(&val, message, &pk),
			Err(err) => {
				log::debug!("Error generating pair {:?}", err);
				false
			}
		},
		Err(_) => false
	}
}

impl BackupRequest {
	fn verify_request(&self) -> Result<bool, BackupError> {
		if !verify_account_id(&self.data.signer_address) {
			return Err(BackupError::UnAuthorizedSigner)
		}

		if verify_signature(
			&self.data.signer_address,
			self.signature.clone(),
			&serde_json::to_vec(&self.data).unwrap(),
		) {
			Ok(true)
		} else {
			Err(BackupError::InvalidSignature)
		}
	}
}

impl StoreRequest {
	fn verify_request(&self) -> Result<bool, BackupError> {
		if !verify_account_id(&self.data.signer_address) {
			return Err(BackupError::UnAuthorizedSigner)
		}

		let message_str = serde_json::to_string(&self.data).unwrap();
		let message_bytes = message_str.as_bytes();

		if verify_signature(&self.data.signer_address, self.signature.clone(), &message_bytes) {
			info!("OK -> message = {:#?}\n", message_str);
			Ok(true)
		} else {
			info!("ERR -> message = {:#?}\n", message_str);
			Err(BackupError::InvalidSignature)
		}
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
			return Json(json! ({
				"status": "Successfull request",
				"data": data,
			}))
		} else {
			return Json(json! ({
				"status": "Authentication Token Expired",
				"data": [],
			}))
		}
	} else {
		return Json(json! ({
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
			return Json(json! ({
				"status": "Successfull request",
			}))
		} else {
			return Json(json! ({
				"status": "Authentication Token Expired",
				"data": [],
			}))
		}
	} else {
		return Json(json! ({
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

/* ******************************
 RETRIEVE KEYSHARES FROM THIS ENCLAVE
****************************** */

#[debug_handler]
pub async fn backup_fetch_keyshares(
	State(state): State<StateConfig>,
	backup_request: String,
) -> impl IntoResponse {
	let parsed_request: BackupRequest = match serde_json::from_str(&backup_request) {
		Ok(preq) => preq,
		Err(e) => {
			info!(
				"Error backup keyshares : Can not deserialize the backup request : {}",
				backup_request
			);

			return (
				StatusCode::OK,
				Json(BackupResponse {
					status: "Error can not deserialize the request : ".to_string() + &e.to_string(),
					data: BTreeMap::new(),
				}),
			)
		},
	};

	let verified_req = parsed_request.verify_request();

	match verified_req {
		Ok(_) => {
			let mut backup_response_data: BTreeMap<String, [String; 2]> = BTreeMap::new();

			for nft_id in parsed_request.data.nfts {
				let file_path = state.seal_path.to_owned() + &nft_id + ".keyshare";
				let log_path = state.seal_path.to_owned() +
					nft_id.split("_").collect::<Vec<&str>>()[1] +
					".log";

				if !std::path::Path::new(&file_path).is_file() {
					info!(
						"Error backup keyshares from TEE : file path does not exist, file_path : {}",
						file_path
					);
					return (
						StatusCode::UNPROCESSABLE_ENTITY,
						Json(BackupResponse {
							status: format!(
								"NFT_ID number {} does not exist on this enclave",
								nft_id
							),
							data: BTreeMap::new(),
						}),
					)
				}

				let mut logfile = std::fs::File::open(log_path).expect("can not open log file"); // TODO: manage expect()

				let mut secfile = match std::fs::File::open(file_path) {
					Ok(file) => file,
					Err(_) => {
						info!(
							"Error backup keyshares from TEE : nft_id does not exist, nft_id : {}",
							nft_id
						);

						return (
							StatusCode::UNPROCESSABLE_ENTITY,
							Json(BackupResponse {
								status: format!("Error retrieving keyshares from TEE : nft_id does not exist, nft_id : {}", nft_id ), 
								data: BTreeMap::new(),
							}),
						);
					},
				};

				let mut nft_keyshare = String::new();
				let mut nft_log = String::new();

				secfile.read_to_string(&mut nft_keyshare).unwrap(); // TODO: manage unwrap()
				logfile.read_to_string(&mut nft_log).unwrap(); // TODO: manage unwrap()

				backup_response_data.insert(nft_id.clone(), [nft_keyshare, nft_log]);

				info!(
					"Key-shares of {} retrieved by {}",
					nft_id, parsed_request.data.signer_address
				);
			}

			return (
				StatusCode::OK,
				Json(BackupResponse {
					status: "Successful".to_string(),
					data: backup_response_data,
				}),
			)
		},

		Err(err) =>
			return (
				StatusCode::OK,
				Json(BackupResponse {
					status: format!("Error Backup Request : {:?}", err),
					data: BTreeMap::new(),
				}),
			),
	}
}

/* *************************
 STORE SECRET TO ENCLAVE
************************* */

//pub async fn backup_push_keyshares(Json(received_data): Json<SecretPacket>) -> impl IntoResponse
#[debug_handler]
pub async fn backup_push_keyshares(
	State(state): State<StateConfig>,
	store_request: String,
) -> impl IntoResponse {
	let parsed_request: StoreRequest = match serde_json::from_str(&store_request) {
		Ok(preq) => preq,
		Err(e) => {
			info!(
				"Error restore keyshares : Can not deserialize the store request : {}",
				store_request
			);

			return (
				StatusCode::OK,
				Json(StoreResponse {
					status: "Error can not deserialize the request : ".to_string() + &e.to_string(),
				}),
			)
		},
	};

	let verified_req = parsed_request.verify_request();

	match verified_req {
		Ok(_) => {
			for (nft_id, [keyshare, viewlog]) in parsed_request.data.nfts {
				std::fs::create_dir_all(state.seal_path.clone()).unwrap(); // TODO: manage unwrap()
				let file_path = state.seal_path.to_owned() + &nft_id + ".keyshare"; // nft or capsule?
				let log_path = state.seal_path.to_owned() +
					&nft_id.split("_").collect::<Vec<&str>>()[1] +
					".log";

				if std::path::Path::new(file_path.as_str()).exists() {
					let message = format!(
						"Error storing keyshares to TEE : nft_id already exists, nft_id = {}",
						nft_id
					);

					log::warn!("{}", message);

					return (StatusCode::OK, Json(StoreResponse { status: message }))
				}

				let mut g = std::fs::File::create(log_path).unwrap(); // TODO: manage unwrap()
				let mut f = match std::fs::File::create(file_path) {
					Ok(file) => file,
					Err(err) => {
						let message = format!("Error storing keyshares to TEE : error in creating file on disk, nft_id = {}, Error = {:?}", nft_id, err);

						log::warn!("{}", message);

						return (StatusCode::OK, Json(StoreResponse { status: message }))
					},
				};

				g.write_all(viewlog.as_bytes()).unwrap(); // TODO: manage unwrap()
				f.write_all(keyshare.as_bytes()).unwrap(); // TODO: manage unwrap()

				log::debug!(
					"Key-share is successfully stored to TEE, nft_id = {} by admin = {}",
					nft_id,
					parsed_request.data.signer_address
				);
			}

			log::info!(
				"All keyshares are successfully stored to TEE by admin = {}",
				parsed_request.data.signer_address
			);

			return (
				StatusCode::OK,
				Json(StoreResponse {
					status: "All keyshares are successfully stored to TEE".to_string(),
				}),
			)
		},

		Err(err) => {
			let message = format!("Error storing keyshares to TEE : {:?}", err);
			log::warn!("{}", message);

			return (StatusCode::OK, Json(StoreResponse { status: message }))
		},
	}
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use hex::FromHexError;
	use tokio_test::assert_err;
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

		let request = FetchBulkPacket {
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

		let request = StoreBulkPacket {
			admin_address: admin_keypair.public().to_string(),
			data,
			signature: sig_str,
		};
	}

	#[tokio::test]
	async fn verification_test() {
		let store_body = r#"
        {
			"data": {
				"nfts": {
					"nft_247": 		["SecretShareNum1ForNFTID247","5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6 Viewed the key-share on 2023-02-21 12:53:38\n"],
					"nft_258":		["SecretShareNum1ForNFTID258","5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6 Viewed the key-share on 2023-02-21 12:53:38\n"],
					"capsule_274":	["SecretShareNum1ForNFTID274","5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6 Viewed the key-share on 2023-02-21 12:53:38\n"]
				},
				"signer_address": "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy"
			},
			"signature":  "6e45e4bf575d8490f94c3d4b7153032735e377354bb7937a8fc538474c2357076f7722005c601c000b109fb4c6a5b41caedf43775267026041dd6d736290db84"
        }"#;

		let store_packet: StoreRequest =
			serde_json::from_str(&store_body.clone()).expect("error in store request json-body");

		match store_packet.verify_request() {
			Ok(_) => info!("Store Request : Key-shares is Valid!"),
			Err(err) => match err {
				BackupError::InvalidSignature => info!("Store Request : Signature Error!"),
				BackupError::UnAuthorizedSigner => info!("Store Request : Unauthorized Admin!"),
			},
		}

		let backup_body = r#"
        {
			"data": {
				"nfts": ["247","258","274"],            
				"signer_address": "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy"
			},
			"signature": "ae2490d6b3bef0811aaab582c7f87026948af3d1b94e839bf37986b78171846229a04ed28de862bea4ebc088117e7a388bae67fc7f738b88a7e09166fb660d88"
        }"#;

		let backup_packet: BackupRequest =
			serde_json::from_str(&backup_body.clone()).expect("error in backup request json-body");

		match backup_packet.verify_request() {
			Ok(_) => info!("Backup Request : Key-share is Valid!"),

			Err(err) => match err {
				BackupError::InvalidSignature => info!("Backup Request : Signature Error!"),
				BackupError::UnAuthorizedSigner => info!("Backup Request : Unauthorized Admin!"),
			},
		}

		/*
		let key_pair = sp_keyring::AccountKeyring::Dave.pair();

		let rc_store_packet_data = serde_json::to_vec::<u8>(&store_packet.data).unwrap();
		let store_sign = key_pair.sign(&rc_store_packet_data);
		info!("rc_store_packet_data : {:#?}\n", rc_store_packet_data);
		info!("store_sign : {:#?}\n", store_sign);

		let rc_backup_packet_data = serde_json::to_vec::<u8>(&backup_packet.data).unwrap();
		let backup_sign = key_pair.sign(&rc_backup_packet_data);
		info!("rc_backup_packet_data : {:#?}\n", rc_backup_packet_data);
		info!("backup_sign: {:#?}\n", backup_sign);
		*/
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
			admin_address: admin_address.to_string(),
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
		assert_eq!(results, sp_core::sr25519::Public::from_ss58check(&account).unwrap());
	}
}
