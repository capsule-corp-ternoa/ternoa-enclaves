use crate::chain::chain::get_nft_data;
use crate::servers::http_server::StateConfig;

use async_trait::async_trait;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use hex::FromHex;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use tracing::{error, info, warn};

use sp_core::{sr25519, ByteArray, Pair};
use subxt::utils::AccountId32;

use axum::extract::Path as PathExtract;

use crate::chain::chain::nft_secret_share_oracle;

/* **********************
	 DATA STRUCTURES
********************** */

/* **********************
	 DATA STRUCTURES
********************** */

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum SecretError {
	InvalidSignature,
	InvalidOwner,
}

#[derive(Serialize)]
pub enum ReturnStatus {
	STORESUCCESS,
	RETRIEVESUCCESS,
	INVALIDSIGNATURE,
	INVALIDOWNER,
	NFTIDEXISTS,
	NFTIDNOTEXIST,
	DATABASEFAILURE,
	ORACLEFAILURE,
	NFTSECRETNOTACCESSIBLE,
	NFTSECRETNOTREADABLE,
}

#[derive(Deserialize, Clone)]

pub struct SecretPacket {
	account_address: sr25519::Public,
	secret_data: String,
	signature: String,
}

#[derive(Serialize)]
pub struct SecretStoreResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

#[derive(Serialize)]
pub struct SecretRetrieveResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	secret_data: String,
	description: String,
}

#[derive(Debug, PartialEq)]
pub enum NFTOwner {
	Owner(AccountId32),
	NotFound,
}

pub async fn get_nft_owner(nft_id: u32) -> NFTOwner {
	let data = get_nft_data(nft_id).await;

	let owner = match data {
		Some(nft_data) => NFTOwner::Owner(nft_data.owner),
		None => NFTOwner::NotFound,
	};

	owner
}

#[derive(Clone)]
pub struct SecretData {
	nft_id: u32,
	data: Vec<u8>,
}

impl SecretData {
	fn serialize(self) -> String {
		self.nft_id.to_string() + "_" + &String::from_utf8(self.data).unwrap()
	}
}

impl SecretPacket {
	fn parse_secret(&self) -> SecretData {
		let mut secret_data = self.secret_data.clone();
		if secret_data.starts_with("<Bytes>") && secret_data.ends_with("</Bytes>") {
			secret_data = secret_data
				.strip_prefix("<Bytes>")
				.unwrap()
				.strip_suffix("</Bytes>")
				.unwrap()
				.to_string();
		}

		let nftid_data: Vec<&str> = if secret_data.contains("_") {
			secret_data.split("_").collect()
		} else {
			vec![&secret_data]
		};

		SecretData {
			nft_id: nftid_data[0].parse::<u32>().unwrap(),
			data: if !nftid_data[1].is_empty() {
				nftid_data[1].as_bytes().to_vec()
			} else {
				Vec::new()
			},
		}
	}
}

#[async_trait]
pub trait VerifyNFT {
	fn get_public_key(&self) -> Result<sr25519::Public, ()>;
	fn parse_signature(&self) -> Result<sr25519::Signature, SignatureError>;
	fn verify_signature(&self) -> bool;
	async fn check_nft_ownership(&self) -> bool;
	async fn verify_receive_data(&self) -> Result<SecretData, SecretError>;
}

#[derive(Debug, PartialEq)]
pub enum SignatureError {
	PREFIXERROR,
	LENGHTERROR,
}

#[async_trait]
impl VerifyNFT for SecretPacket {
	fn get_public_key(&self) -> Result<sr25519::Public, ()> {
		sr25519::Public::from_slice(self.account_address.clone().as_slice())
	}

	fn parse_signature(&self) -> Result<sr25519::Signature, SignatureError> {
		let strip_sig = match self.signature.strip_prefix("0x") {
			Some(ssig) => ssig,
			_ => return Err(SignatureError::PREFIXERROR),
		};

		let sig_bytes = match <[u8; 64]>::from_hex(strip_sig) {
			Ok(bsig) => bsig,
			Err(_) => return Err(SignatureError::LENGHTERROR),
		};

		Ok(sr25519::Signature::from_raw(sig_bytes))
	}

	fn parse_signature(&self) -> Result<sr25519::Signature, SignatureError> {
		let strip_sig = match self.signature.strip_prefix("0x") {
			Some(ssig) => ssig,
			_ => return Err(SignatureError::PREFIXERROR),
		};

		let sig_bytes = match <[u8; 64]>::from_hex(strip_sig) {
			Ok(bsig) => bsig,
			Err(_) => return Err(SignatureError::LENGHTERROR),
		};
		
		Ok(sr25519::Signature::from_raw(sig_bytes))
	}

	fn verify_signature(&self) -> bool {
		let account_pubkey = match self.get_public_key() {
			Ok(pk) => pk,
			Err(_) => return false,
		};

		let signature = match self.parse_signature() {
			Ok(sig) => sig,
			Err(_) => return false,
		};

		sr25519::Pair::verify(&signature, self.secret_data.clone(), &account_pubkey)
	}

	async fn check_nft_ownership(&self) -> bool {
		let nft_owner = get_nft_owner(self.parse_secret().nft_id).await;
		match nft_owner {
			NFTOwner::Owner(owner) => owner == self.account_address.into(),
			NFTOwner::NotFound => false,
		}
	}

	async fn verify_receive_data(&self) -> Result<SecretData, SecretError> {
		if self.verify_signature() {
			if self.check_nft_ownership().await {
				Ok(self.parse_secret())
			} else {
				Err(SecretError::InvalidOwner)
			}
		} else {
			Err(SecretError::InvalidSignature)
		}
	}
}

/* **********************
	 SECRET VIEW API
********************** */
#[derive(Serialize)]
pub struct NFTViewResponse {
	enclave_id: String,
	nft_id: u32,
	log: String,
}

// TODO: check the request for signed data and prevent flooding requests.
pub async fn get_nft_views_handler(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let file_path = state.seal_path + &nft_id.to_string() + ".log";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Log path checked, path: {}", file_path);
	} else {
		error!(
			"Error retrieving secret log : log path doe not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::OK,
			Json(NFTViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: "nft_id does not exist on this enclave".to_string(),
			}),
		);
	};

	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(_) => {
			error!(
				"Error retrieving secret log : can not open the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::OK,
				Json(NFTViewResponse {
					enclave_id: state.identity,
					nft_id,
					log: "can not retrieve the log of nft views".to_string(),
				}),
			);
		},
	};

	let mut log_data = String::new();
	match log_file.read_to_string(&mut log_data) {
		Ok(_) => {
			info!("successfully retrieved log file for nft_id : {}", nft_id);
			return (
				StatusCode::OK,
				Json(NFTViewResponse { enclave_id: state.identity, nft_id, log: log_data }),
			);
		},

		Err(_) => {
			error!(
				"Error retrieving secret log : can not read the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::OK,
				Json(NFTViewResponse {
					enclave_id: state.identity,
					nft_id,
					log: "can not retrieve the log of nft views".to_string(),
				}),
			);
		},
	};
}

/* **********************
	 STORE SECRET
********************** */

pub async fn store_secret_shares(
	State(state): State<StateConfig>,
	Json(received_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_secret = received_secret.verify_receive_data().await;

	match verified_secret {
		Ok(secret) => {
			if std::path::Path::new(&state.clone().seal_path).exists() {
				info!("Seal path checked, path: {}", state.seal_path.clone());
			} else {
				error!("Error storing secrets to TEE : seal path doe not exist, nft_id : {}, path : {}", secret.nft_id, state.seal_path);

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::DATABASEFAILURE,
						nft_id: secret.nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE, use another enclave please."
							.to_string(),
					}),
				);
			};

			let file_path = state.seal_path.clone() + &secret.nft_id.to_string() + ".secret";
			let exist = std::path::Path::new(file_path.as_str()).exists();

			if exist {
				warn!(
					"Error storing secrets to TEE : nft_id already exists, nft_id = {}",
					secret.nft_id
				);

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::NFTIDEXISTS,
						nft_id: secret.nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : nft_id already exists"
							.to_string(),
					}),
				);
			}

			let mut f = match std::fs::File::create(file_path.clone()) {
				Ok(file) => file,
				Err(err) => {
					error!("Error storing secrets to TEE : error in creating file on disk, nft_id : {}, path : {}, Error : {}", secret.nft_id, file_path, err);

					return (
						StatusCode::OK,
						Json(SecretStoreResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description:
								"Error storing secrets to TEE, use another enclave please."
									.to_string(),
						}),
					);
				},
			};

			match f.write_all(&secret.data) {
				Ok(_) => info!(
					"Secret is successfully stored to TEE, nft_id = {}  Owner = {}",
					secret.nft_id, received_secret.account_address
				),
				Err(err) => {
					error!("Error storing secrets to TEE : error in writing data to file, nft_id : {}, path: {}, Error : {}", secret.nft_id, file_path, err);

					return (
						StatusCode::OK,
						Json(SecretStoreResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description:
								"Error storing secrets to TEE, use another enclave please."
									.to_string(),
						}),
					);
				},
			};

			// Send extrinsic to Secret-NFT Pallet as Storage-Oracle
			match nft_secret_share_oracle(state.enclave_key.clone(), secret.nft_id).await {
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to secret-nft-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
						secret.nft_id, received_secret.account_address, txh
					);

					// Log file for tracing the secrets VIEW history in Marketplace.
					let file_path = state.seal_path + &secret.nft_id.to_string() + ".log";
					std::fs::File::create(file_path.clone()).unwrap();

					return (
						StatusCode::OK,
						Json(SecretStoreResponse {
							status: ReturnStatus::STORESUCCESS,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description: "Secret is successfully stored to TEE".to_string(),
						}),
					);
				},

				Err(err) => {
					error!(
						"Error sending proof of storage to chain, nft_id : {}, Error : {}",
						secret.nft_id, err
					);

					std::fs::remove_file(file_path.clone()).expect("Can not remove secret file");

					return (
						StatusCode::OK,
						Json(SecretStoreResponse {
							status: ReturnStatus::ORACLEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description: "Error sending proof of storage to chain.".to_string(),
						}),
					);
				},
			}
		},

		Err(err) => match err {
			SecretError::InvalidSignature => {
				warn!("Error storing secrets to TEE : Invalid Request Signature");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::INVALIDSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Invalid Request Signature"
							.to_string(),
					}),
				);
			},

			SecretError::InvalidOwner => {
				warn!("Error storing secrets to TEE : Invalid NFT Owner");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::INVALIDOWNER,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Invalid NFT Owner".to_string(),
					}),
				);
			},
		},
	}
}

/* **********************
	 RETRIEVE SECRET
********************** */

pub async fn retrieve_secret_shares(
	State(state): State<StateConfig>,
	Json(requested_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_req = requested_secret.verify_receive_data().await;

	match verified_req {
		Ok(data) => {
			let file_path = state.seal_path.clone() + &data.nft_id.to_string() + ".secret";
			if !std::path::Path::new(&file_path).is_file() {
				warn!(
					"Error retrieving secrets from TEE : file path does not exist, file_path : {}",
					file_path
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::NFTIDNOTEXIST,
						nft_id: data.nft_id,
						enclave_id: state.identity,
						description: "Error retrieving secrets from TEE : nft_id does not exist"
							.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			}

			let mut file = match std::fs::File::open(file_path) {
				Ok(file) => file,
				Err(err) => {
					error!("Error retrieving secrets from TEE : can not open secret file, nft_id : {} Error : {}", data.nft_id, err);

					return (
						StatusCode::OK,
						Json(SecretRetrieveResponse {
							status: ReturnStatus::NFTSECRETNOTACCESSIBLE,
							nft_id: data.nft_id,
							enclave_id: state.identity,
							description:
								"Error retrieving secrets from TEE : nft_id does not exist"
									.to_string(),
							secret_data: "_".to_string(),
						}),
					);
				},
			};

			let mut nft_secret_share = Vec::<u8>::new();

			match file.read_to_end(&mut nft_secret_share) {
				Ok(_) => info!(
					"Secret shares of {} retrieved by {}",
					data.nft_id, requested_secret.account_address
				),

				Err(err) => {
					error!("Error retrieving secrets from TEE : can not read secret file, nft_id : {} Error : {}", data.nft_id, err);

					return (
						StatusCode::OK,
						Json(SecretRetrieveResponse {
							status: ReturnStatus::NFTSECRETNOTREADABLE,
							nft_id: data.nft_id,
							enclave_id: state.identity,
							description:
								"Error retrieving secrets from TEE : can not read secret data"
									.to_string(),
							secret_data: "_".to_string(),
						}),
					);
				},
			};

			// Put a VIEWING history log
			let file_path = state.seal_path + &data.nft_id.to_string() + ".log";
			let mut log_file = OpenOptions::new()
				.append(true)
				.open(file_path)
				.expect("Unable to open log file");

			log_file.seek(std::io::SeekFrom::End(0)).unwrap();

			let time: chrono::DateTime<chrono::offset::Utc> = std::time::SystemTime::now().into();
			let log_data = requested_secret.account_address.to_string()
				+ " Viewed the secret on "
				+ time.format("%Y-%m-%d %H:%M:%S").to_string().as_str()
				+ "\n";

			log_file.write(log_data.as_bytes()).expect("write to log failed");

			return (
				StatusCode::OK,
				Json(SecretRetrieveResponse {
					status: ReturnStatus::RETRIEVESUCCESS,
					nft_id: data.nft_id,
					enclave_id: state.identity,
					description: "Success retrieving nft_id secret share.".to_string(),
					secret_data: SecretData { nft_id: data.nft_id, data: nft_secret_share }
						.serialize(),
				}),
			);
		},

		Err(err) => match err {
			SecretError::InvalidSignature => {
				info!(
					"Error retrieving secrets from TEE : Invalid Signature, owner : {}",
					requested_secret.account_address
				);

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDSIGNATURE,
						nft_id: 0,
						enclave_id: state.identity,
						description: "Error Invalid Signature or NFT owner".to_string(),
						secret_data: SecretData { nft_id: 0, data: Vec::new() }.serialize(),
					}),
				);
			},

			SecretError::InvalidOwner => {
				info!(
					"Error retrieving secrets from TEE : Invalid Owner, owner : {}",
					requested_secret.account_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						nft_id: 0,
						enclave_id: state.identity,
						description: "Error Invalid NFT owner".to_string(),
						secret_data: SecretData { nft_id: 0, data: Vec::new() }.serialize(),
					}),
				);
			},
		},
	}
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;
	use sp_keyring::AccountKeyring;
	use sp_runtime::app_crypto::Ss58Codec;
	/* TODO: This test can not pass in workflow action, without verified account and nft_id
	#[tokio::test]
	async fn get_nft_owner_test() {
		let address = AccountId32::from(
			sr25519::Public::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6")
				.unwrap(),
		);
		let nft_id = 10;
		let owner = match get_nft_owner(nft_id).await {
			NFTOwner::Owner(addr) => addr,
			NFTOwner::NotFound => panic!("Test erros, nft_id is not available, check your chain."),
		};
		let other = match get_nft_owner(nft_id + 100).await {
			NFTOwner::Owner(addr) => addr,
			NFTOwner::NotFound => panic!("Test erros, nft_id is not available, check your chain."),
		};
		let unknown = get_nft_owner(10_000).await;

		assert_eq!(owner, address); // Same NFT match Owner
		assert_ne!(other, address); // Different NFTs, (probably) diffetent owners
		assert_ne!(owner, AccountKeyring::Alice.to_raw_public().into()); // Unauthorized random owner
		assert_eq!(unknown, NFTOwner::NotFound); // Unavailable NFT
	}
	*/
	#[tokio::test]
	async fn parse_secret_from_sdk_test() {
		let secret_packet_sdk: SecretPacket = SecretPacket {
			account_address: sr25519::Public::from_slice(&[0u8;32]).unwrap(),
			secret_data: "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
		};

		// Signed in SDK
		let secret_data = secret_packet_sdk.parse_secret();

		assert_eq!(secret_data.nft_id, 10);
		assert_eq!(secret_data.data, b"CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU");
	}

	#[tokio::test]
	async fn parse_secret_from_polkadotjs_test() {
		let secret_packet_polkadotjs:SecretPacket = SecretPacket {
			account_address: sr25519::Public::from_slice(&[0u8;32]).unwrap(),
			secret_data: "<Bytes>247_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU</Bytes>".to_string(), 
			signature: "xxx".to_string(),
		};
		// Signed in Polkadot.JS
		let secret_data = secret_packet_polkadotjs.parse_secret();

		assert_eq!(secret_data.nft_id, 247);
		assert_eq!(secret_data.data, b"CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU");
	}

	#[tokio::test]
	async fn get_public_key_test() {
		let secret_packet_sdk: SecretPacket = SecretPacket {
			account_address: sr25519::Public::from_ss58check(
				"5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6",
			)
			.unwrap(),
			secret_data: "xxx".to_string(),
			signature: "xxx".to_string(),
		};

		let pk = secret_packet_sdk.get_public_key().unwrap();

		assert_eq!(
			pk.as_slice(),
			<[u8; 32]>::from_hex(
				"1a40e806c28a32dbac60f2b088c77a9ac3d3702011ac0e13579402ddcc214308"
			)
			.unwrap()
		);
	}

	#[tokio::test]
	async fn parse_signature_test() {
		let correct_sig = sr25519::Signature::from_raw(<[u8;64]>::from_hex("42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b").unwrap());

		let mut secret_packet_sdk: SecretPacket = SecretPacket {
			account_address: sr25519::Public::from_slice(&[0u8;32]).unwrap(),
			secret_data: "xxx".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
		};

		let sig = secret_packet_sdk.parse_signature().unwrap();
		assert_eq!(sig, correct_sig);

		// 0x prefix
		secret_packet_sdk.signature = "42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		let sig = secret_packet_sdk.parse_signature().unwrap_err();
		assert_eq!(sig, SignatureError::PREFIXERROR);

		// Length
		secret_packet_sdk.signature = "0x2bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		let sig = secret_packet_sdk.parse_signature().unwrap_err();
		assert_eq!(sig, SignatureError::LENGHTERROR);
	}

	#[tokio::test]
	async fn verify_signature_test() {
		let mut secret_packet = SecretPacket {
			account_address: sr25519::Public::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6").unwrap(),
			secret_data: "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
		};

		assert_eq!(secret_packet.verify_signature(), true);

		// changed secret
		secret_packet.secret_data = "10_DAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string();
		assert_eq!(secret_packet.verify_signature(), false);

		// changed owner
		secret_packet.account_address =
			sr25519::Public::from_slice(&AccountKeyring::Alice.to_raw_public()).unwrap();
		secret_packet.secret_data = "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string();
		assert_eq!(secret_packet.verify_signature(), false);

		// changed signature
		secret_packet.account_address =
			sr25519::Public::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6")
				.unwrap();
		secret_packet.signature = "0x32bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		assert_eq!(secret_packet.verify_signature(), false);
	}

	#[tokio::test]
	async fn full_verify_received_data_test() {
		let secret_packet = SecretPacket {
			account_address: sr25519::Public::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6").unwrap(),
			secret_data: "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
		};

		let key_pair1 = sr25519::Pair::from_string_with_seed(
			"broccoli tornado verb crane mandate wise gap shop mad quarter jar snake",
			None,
		)
		.unwrap()
		.0;

		let _key_pair2 = AccountKeyring::Dave.pair();

		let _public1 = key_pair1.clone().public();
		let public2 = sr25519::Public::from_raw(AccountKeyring::Dave.to_raw_public());

		let message1 = secret_packet.secret_data.as_bytes();
		let message2 = b"<Bytes>247_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU</Bytes>";

		let sig1_bytes =
			<[u8; 64]>::from_hex(secret_packet.signature.clone().strip_prefix("0x").unwrap())
				.unwrap();
		let signature1 = sr25519::Signature::from_raw(sig1_bytes);
		let sig2_bytes = <[u8; 64]>::from_hex("0x1ae93ac6f0ee8b0edec9d221371f46ce93e68fdfa9e5d68428fd1c93dc46560c1b4caba9edae2a6a299b5c7e3dfa53bb2f852848b48eae18d359c014fa188487".strip_prefix("0x").unwrap()).unwrap();
		let signature2 = sr25519::Signature::from_raw(sig2_bytes); //key_pair2.sign(message2);

		let vr1 = sr25519::Pair::verify(
			&signature1,
			message1,
			&sr25519::Public::from_slice(&secret_packet.account_address.as_slice()).unwrap(), /* public1 */
		);
		let vr2 = sr25519::Pair::verify(&signature2, message2, &public2);

		info!("res1 : {}\nres2 : {}", vr1, vr2);

		match secret_packet.verify_receive_data().await {
			Ok(_) => info!("Secret is Valid!"),

			Err(err) => match err {
				SecretError::InvalidSignature => info!("Signature Error!"),

				SecretError::InvalidOwner => info!("Invalid Owner!"),
			},
		}
	}
}
