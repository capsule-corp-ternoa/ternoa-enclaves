use axum::{
	body::Body,
	debug_handler,
	http::{Request, StatusCode},
	response::IntoResponse,
	Json,
};

use hex::{FromHex, ToHex};
use std::{
	collections::HashMap,
	io::{Read, Write},
};
use subxt::ext::sp_runtime::app_crypto::Ss58Codec;

use subxt::ext::{
	sp_core::{sr25519, Pair},
	sp_runtime::AccountId32,
};

use serde::{Deserialize, Serialize};

const NFT_DIR_PATH: &str = "./credentials/nft/";
const BACKUP_WHITELIST: [&str; 2] = ["ABCDEF123450", "5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6"];

#[derive(Debug)]
pub enum BackupError {
	DecodeError,
	UnAuthorizedSigner,
	InvalidSignature,
}

// -------- Backup -------
#[derive(Serialize, Deserialize, Clone)]
pub struct BackupRequestData {
	signerAddress: String,
	nfts: Vec<u32>,
}

#[derive(Deserialize, Clone)]
pub struct BackupRequest {
	data: BackupRequestData,
	signature: String,
}

#[derive(Serialize)]
pub struct BackupResponse {
	status: String,
	data: HashMap<String, String>,
}

// -------- Store -------

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreRequestData {
	signerAddress: String,
	nfts: HashMap<String, String>,
}

#[derive(Deserialize, Clone)]
pub struct StoreRequest {
	data: StoreRequestData,
	signature: String,
}

#[derive(Serialize)]
pub struct StoreResponse {
	status: String,
}

fn verify_accountId(accountId: &str) -> bool {
	BACKUP_WHITELIST.contains(&accountId)
}

fn get_public_key(accountId: &str) -> sr25519::Public {
	sr25519::Public::from_ss58check(accountId).expect("Valid address")
}

fn get_signature(signature: String) -> sr25519::Signature {
	let sig_bytes = <[u8; 64]>::from_hex(signature.strip_prefix("0x").unwrap()).unwrap();
	sr25519::Signature::from_raw(sig_bytes)
}

fn verify_signature(accountId: &str, signature: String, message: &[u8]) -> bool {
	let account_pubkey = get_public_key(accountId);
	//let encoded: Vec<u8> = bincode::serialize(&self.secret_data).unwrap();
	sr25519::Pair::verify(&get_signature(signature), message.clone(), &account_pubkey)
}

impl BackupRequest {
	fn verify_request(&self) -> Result<bool, BackupError> {
		if !verify_accountId(&self.data.signerAddress) {
			return Err(BackupError::UnAuthorizedSigner)
		}

		if verify_signature(
			&self.data.signerAddress,
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
		if !verify_accountId(&self.data.signerAddress) {
			return Err(BackupError::UnAuthorizedSigner)
		}

		if verify_signature(
			&self.data.signerAddress,
			self.signature.clone(),
			&serde_json::to_string(&self.data).unwrap().as_bytes(),
		) {
			Ok(true)
		} else {
			Err(BackupError::InvalidSignature)
		}
	}
}

/* RETRIEVE SECRET */
#[debug_handler]
pub async fn backup_fetch_secrets(backup_request: String) -> impl IntoResponse {
	let parsed_request: BackupRequest = match serde_json::from_str(&backup_request) {
		Ok(preq) => preq,
		Err(e) => {
			println!(
				"Error backup secret : Can not deserialize the backup request : {}",
				backup_request
			);

			return (
				StatusCode::OK,
				Json(BackupResponse {
					status: "Error can not deserialize the request : ".to_string() + &e.to_string(),
					data: HashMap::new(),
				}),
			)
		},
	};

	let verified_req = parsed_request.verify_request();

	match verified_req {
		Ok(_) => {
			let mut backup_response_data: HashMap<String, String> = HashMap::new();

			for nft_id in parsed_request.data.nfts {
				let file_path = NFT_DIR_PATH.to_owned() + &nft_id.to_string() + ".secret";

				if !std::path::Path::new(&file_path).is_file() {
					println!(
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
							data: HashMap::new(),
						}),
					)
				}

				let mut file = match std::fs::File::open(file_path) {
					Ok(file) => file,
					Err(_) => {
						println!(
							"Error backup secrets from TEE : nft_id does not exist, nft_id : {}",
							nft_id
						);

						return (
							StatusCode::UNPROCESSABLE_ENTITY,
							Json(BackupResponse {
								status: format!("Error retrieving secrets from TEE : nft_id does not exist, nft_id : {}", nft_id ), 
								data: HashMap::new(),
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
					parsed_request.data.signerAddress
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
					data: HashMap::new(),
				}),
			),
	}
}

/* STORE SECRET */

//pub async fn backup_push_secrets(Json(received_secret): Json<SecretPacket>) -> impl IntoResponse
#[debug_handler]
pub async fn backup_push_secrets(store_request: String) -> impl IntoResponse {
	let parsed_request: StoreRequest = match serde_json::from_str(&store_request) {
		Ok(preq) => preq,
		Err(e) => {
			println!(
				"Error restore secret : Can not deserialize the store request : {}",
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
			for (nft_id, secret) in parsed_request.data.nfts {
				std::fs::create_dir_all(NFT_DIR_PATH).unwrap();
				let file_path = NFT_DIR_PATH.to_owned() + &nft_id.to_string() + ".secret";

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
					parsed_request.data.signerAddress
				);
			}

			log::info!(
				"All Secrets are successfully stored to TEE by admin = {}",
				parsed_request.data.signerAddress
			);

			return (
				StatusCode::OK,
				Json(StoreResponse {
					status: "All Secrets are successfully stored to TEE".to_string(),
				}),
			)
		},

		Err(err) => {
			let message = format!("Error storing secrets to TEE : {:?}", err);
			log::warn!("{}", message);

			return (StatusCode::OK, Json(StoreResponse { status: message }))
		},
	}
}

/* TEST */
#[cfg(test)]
mod test {
	use super::*;
	//use bincode::serialize;
	//use hex_literal::hex;
	use sp_keyring::AccountKeyring;
	use subxt::ext::sp_runtime::app_crypto::Ss58Codec;

	#[tokio::test]
	async fn verification_test() {
		
		let store_data = StoreRequestData {
			nfts: HashMap::from([
				(247.to_string(),"SecretShareNum1ForNFTID247".to_string()),
				(258.to_string(),"SecretShareNum1ForNFTID258".to_string()),
				(274.to_string(),"SecretShareNum1ForNFTID274".to_string()),
			]),

			signerAddress: "5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6".to_string()
		};

		let store_packet = StoreRequest {
			data: store_data.clone(),
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
		};

		let backup_data = BackupRequestData {
			nfts: [247,278].to_vec(),
			signerAddress: "5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6".to_string(),
		};

		let backup_packet = BackupRequest {
			data: backup_data.clone(),
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
		};

		let key_pair1 = sr25519::Pair::from_string_with_seed(
			"broccoli tornado verb crane mandate wise gap shop mad quarter jar snake",
			None,
		)
		.unwrap()
		.0;

		let key_pair2 = AccountKeyring::Dave.pair();

		let public1 = key_pair1.clone().public();
		let public2 = key_pair2.clone().public();

		let message1 = serde_json::to_vec(&store_data.clone()).unwrap();
		let message2 = serde_json::to_vec(&backup_data.clone()).unwrap();

		let sig1_bytes =
			<[u8; 64]>::from_hex(store_packet.signature.clone().strip_prefix("0x").unwrap())
				.unwrap();
		let signature1 = sr25519::Signature::from_raw(sig1_bytes);
		let sig2_bytes = <[u8; 64]>::from_hex(backup_packet.signature.strip_prefix("0x").unwrap()).unwrap();
		let signature2 = sr25519::Signature::from_raw(sig2_bytes); //key_pair2.sign(message2);

		let vr1 = sr25519::Pair::verify(
			&signature1,
			message1,
			&sr25519::Public::from_ss58check(&store_data.signerAddress).unwrap(), /* public1 */
		);
		let vr2 = sr25519::Pair::verify(&signature2, message2, &public2);

		println!("res1 : {}\nres2 : {}", vr1, vr2);

		match store_packet.verify_request() {
			Ok(_) => println!("Secret is Valid!"),

			Err(err) => match err {
				BackupError::InvalidSignature => println!("Signature Error!"),
				BackupError::UnAuthorizedSigner => println!("Invalid Owner!"),
				BackupError::DecodeError => println!("Decode Error"),
			},
		}
	}
}
