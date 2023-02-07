use axum::{debug_handler, extract::State, http::StatusCode, response::IntoResponse, Json};

use hex::FromHex;
use sp_core::{sr25519, Pair};
use std::{
	collections::BTreeMap,
	io::{Read, Write},
};

use tracing::info;

use serde::{Deserialize, Serialize};

use crate::servers::http_server::StateConfig;

const BACKUP_WHITELIST: [&str; 2] = [
	"5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",
	"5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6",
];

/* ******************************
		 DATA STRUCTURES
****************************** */

#[derive(Debug)]
pub enum BackupError {
	UnAuthorizedSigner,
	InvalidSignature,
}

// -------- Backup -------
#[derive(Serialize, Deserialize, Clone)]
pub struct BackupRequestData {
	nfts: Vec<u32>,
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
	data: BTreeMap<String, String>,
}

// -------- Store -------

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct StoreRequestData {
	nfts: BTreeMap<String, String>,
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

fn verify_account_id(account_id: &str) -> bool {
	BACKUP_WHITELIST.contains(&account_id)
}

fn get_public_key(account_id: &str) -> sr25519::Public {
	let pk = <sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check(account_id)
		.expect("Invalid AccountID");
	log::debug!("Public Key = {}", pk);
	pk
}

fn get_signature(signature: String) -> sr25519::Signature {
	let stripped = match signature.strip_prefix("0x") {
		Some(sig) => sig,
		None => signature.as_str(),
	};

	let sig_bytes = <[u8; 64]>::from_hex(stripped).unwrap();
	let sig = sr25519::Signature::from_raw(sig_bytes);
	log::debug!("sig = {:#?}", sig);
	sig
}

fn verify_signature(account_id: &str, signature: String, message: &[u8]) -> bool {
	let account_pubkey = get_public_key(account_id);
	let check = sr25519::Pair::verify(&get_signature(signature), message.clone(), &account_pubkey);
	check
}

impl BackupRequest {
	fn verify_request(&self) -> Result<bool, BackupError> {
		if !verify_account_id(&self.data.signer_address) {
			return Err(BackupError::UnAuthorizedSigner);
		}

		if verify_signature(
			&self.data.signer_address,
			self.signature.clone(),
			&serde_json::to_string(&self.data).unwrap().as_bytes(),
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
			return Err(BackupError::UnAuthorizedSigner);
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

/* ******************************
 RETRIEVE SECRET FROM ENCALVE
****************************** */

#[debug_handler]
pub async fn backup_fetch_secrets(
	State(state): State<StateConfig>,
	backup_request: String,
) -> impl IntoResponse {
	let parsed_request: BackupRequest = match serde_json::from_str(&backup_request) {
		Ok(preq) => preq,
		Err(e) => {
			info!(
				"Error backup secret : Can not deserialize the backup request : {}",
				backup_request
			);

			return (
				StatusCode::OK,
				Json(BackupResponse {
					status: "Error can not deserialize the request : ".to_string() + &e.to_string(),
					data: BTreeMap::new(),
				}),
			);
		},
	};

	let verified_req = parsed_request.verify_request();

	match verified_req {
		Ok(_) => {
			let mut backup_response_data: BTreeMap<String, String> = BTreeMap::new();

			for nft_id in parsed_request.data.nfts {
				let file_path = state.seal_path.to_owned() + &nft_id.to_string() + ".secret";

				if !std::path::Path::new(&file_path).is_file() {
					info!(
						"Error backup secrets from TEE : file path does not exist, file_path : {}",
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
					);
				}

				let mut file = match std::fs::File::open(file_path) {
					Ok(file) => file,
					Err(_) => {
						info!(
							"Error backup secrets from TEE : nft_id does not exist, nft_id : {}",
							nft_id
						);

						return (
							StatusCode::UNPROCESSABLE_ENTITY,
							Json(BackupResponse {
								status: format!("Error retrieving secrets from TEE : nft_id does not exist, nft_id : {}", nft_id ), 
								data: BTreeMap::new(),
							}),
						);
					},
				};

				let mut nft_secret_share = String::new();

				file.read_to_string(&mut nft_secret_share).unwrap();

				backup_response_data.insert(nft_id.to_string(), nft_secret_share);

				log::debug!(
					"Secret shares of {} retrieved by {}",
					nft_id,
					parsed_request.data.signer_address
				);
			}

			return (
				StatusCode::OK,
				Json(BackupResponse {
					status: "Successful".to_string(),
					data: backup_response_data,
				}),
			);
		},

		Err(err) => {
			return (
				StatusCode::OK,
				Json(BackupResponse {
					status: format!("Error Backup Request : {:?}", err),
					data: BTreeMap::new(),
				}),
			)
		},
	}
}

/* *************************
 STORE SECRET TO ENCLAVE
************************* */

//pub async fn backup_push_secrets(Json(received_secret): Json<SecretPacket>) -> impl IntoResponse
#[debug_handler]
pub async fn backup_push_secrets(
	State(state): State<StateConfig>,
	store_request: String,
) -> impl IntoResponse {
	let parsed_request: StoreRequest = match serde_json::from_str(&store_request) {
		Ok(preq) => preq,
		Err(e) => {
			info!(
				"Error restore secret : Can not deserialize the store request : {}",
				store_request
			);

			return (
				StatusCode::OK,
				Json(StoreResponse {
					status: "Error can not deserialize the request : ".to_string() + &e.to_string(),
				}),
			);
		},
	};

	let verified_req = parsed_request.verify_request();

	match verified_req {
		Ok(_) => {
			for (nft_id, secret) in parsed_request.data.nfts {
				std::fs::create_dir_all(state.seal_path.clone()).unwrap();
				let file_path = state.seal_path.to_owned() + &nft_id.to_string() + ".secret";

				if std::path::Path::new(file_path.as_str()).exists() {
					let message = format!(
						"Error storing secrets to TEE : nft_id already exists, nft_id = {}",
						nft_id
					);

					log::warn!("{}", message);

					return (StatusCode::OK, Json(StoreResponse { status: message }));
				}

				let mut f = match std::fs::File::create(file_path) {
					Ok(file) => file,
					Err(err) => {
						let message = format!("Error storing secrets to TEE : error in creating file on disk, nft_id = {}, Error = {:?}", nft_id, err);

						log::warn!("{}", message);

						return (StatusCode::OK, Json(StoreResponse { status: message }));
					},
				};

				f.write_all(secret.as_bytes()).unwrap();

				log::debug!(
					"Secret is successfully stored to TEE, nft_id = {} by admin = {}",
					nft_id,
					parsed_request.data.signer_address
				);
			}

			log::info!(
				"All Secrets are successfully stored to TEE by admin = {}",
				parsed_request.data.signer_address
			);

			return (
				StatusCode::OK,
				Json(StoreResponse {
					status: "All Secrets are successfully stored to TEE".to_string(),
				}),
			);
		},

		Err(err) => {
			let message = format!("Error storing secrets to TEE : {:?}", err);
			log::warn!("{}", message);

			return (StatusCode::OK, Json(StoreResponse { status: message }));
		},
	}
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;

	#[tokio::test]
	async fn verification_test() {
		let store_body = r#"
        {
			"data": {
				"nfts": {
					"247": "SecretShareNum1ForNFTID247",
					"258": "SecretShareNum1ForNFTID258",
					"274": "SecretShareNum1ForNFTID274"
				},
				"signer_address": "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy"
			},
			"signature":  "6e45e4bf575d8490f94c3d4b7153032735e377354bb7937a8fc538474c2357076f7722005c601c000b109fb4c6a5b41caedf43775267026041dd6d736290db84"
        }"#;

		let store_packet: StoreRequest =
			serde_json::from_str(&store_body.clone()).expect("error in store request json-body");

		match store_packet.verify_request() {
			Ok(_) => info!("Store Request : Secret is Valid!"),
			Err(err) => match err {
				BackupError::InvalidSignature => info!("Store Request : Signature Error!"),
				BackupError::UnAuthorizedSigner => info!("Store Request : Unauthorized Admin!"),
			},
		}

		let backup_body = r#"
        {
			"data": {
				"nfts": [247,258,274],            
				"signer_address": "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy"
			},
			"signature": "ae2490d6b3bef0811aaab582c7f87026948af3d1b94e839bf37986b78171846229a04ed28de862bea4ebc088117e7a388bae67fc7f738b88a7e09166fb660d88"
        }"#;

		let backup_packet: BackupRequest =
			serde_json::from_str(&backup_body.clone()).expect("error in backup request json-body");

		match backup_packet.verify_request() {
			Ok(_) => info!("Backup Request : Secret is Valid!"),

			Err(err) => match err {
				BackupError::InvalidSignature => info!("Backup Request : Signature Error!"),
				BackupError::UnAuthorizedSigner => info!("Backup Request : Unauthorized Admin!"),
			},
		}

		/*
		let key_pair = sp_keyring::AccountKeyring::Dave.pair();

		let rc_store_packet_data = serde_json::to_string(&store_packet.data).unwrap();
		let store_sign = key_pair.sign(rc_store_packet_data.as_bytes());
		info!("rc_store_packet_data : {:#?}\n", rc_store_packet_data);
		info!("store_sign : {:#?}\n", store_sign);

		let rc_backup_packet_data = serde_json::to_string(&backup_packet.data).unwrap();
		let backup_sign = key_pair.sign(rc_backup_packet_data.as_bytes());
		info!("rc_backup_packet_data : {:#?}\n", rc_backup_packet_data);
		info!("backup_sign: {:#?}\n", backup_sign);
		*/
	}
}
