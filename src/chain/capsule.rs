use crate::servers::http_server::StateConfig;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use hex::FromHex;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::str::FromStr;
use tracing::{error, info, warn};

use sp_core::{sr25519, ByteArray, Pair};
use subxt::utils::AccountId32;

use axum::extract::Path as PathExtract;

use crate::chain::chain::{capsule_secret_share_oracle, get_current_block_number, get_capsule_data};
use crate::chain::verify::*;


/* **********************
	 DATA STRUCTURES
********************** */

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum SecretError {
	InvalidSignature,
	InvalidOwner,
	InvalidSigner,
}

#[derive(Serialize)]
pub enum ReturnStatus {
	STORESUCCESS,
	RETRIEVESUCCESS,
	SECRETCHANGED,
	SECRETREMOVED,

	INVALIDSIGNERSIGNATURE,
	INVALIDOWNERSIGNATURE,

	INVALIDOWNER,
	INVALIDSIGNER,

	EXPIREDSIGNER,
	EXPIREDREQUEST,

	CAPSULEIDEXISTS,
	CAPSULEIDNOTEXIST,

	DATABASEFAILURE,
	ORACLEFAILURE,

	CAPSULESECRETNOTACCESSIBLE,
	CAPSULESECRETNOTREADABLE,

	CAPSULENOTBURNT,
	CAPSULENOTSYNCING,
}

// Errors when parsing signature
#[derive(Debug, PartialEq)]
pub enum SignatureError {
	PREFIXERROR,
	LENGHTERROR,
	TYPEERROR,
}

// Errors
#[derive(Debug, PartialEq)]
pub enum VerificationError {
	INVALIDSIGNERSIG(SignatureError),
	INVALIDOWNERSIG(SignatureError),

	SIGNERVERIFICATIONFAILED,
	OWNERVERIFICATIONFAILED,

	INVALIDOWNER,
	INVALIDSIGNER,

	EXPIREDSIGNER,
	EXPIREDSECRET,
}

// Validity time of Secret Data
#[derive(Clone)]
pub struct AuthenticationToken {
	block_number: u32,
	block_validation: u32,
}

// Secret Data structure
#[derive(Clone)]
pub struct SecretData {
	nft_id: u32,
	data: Vec<u8>,
	auth_token: AuthenticationToken,
}

// Packet-signer and validity of it
#[derive(Clone)]
pub struct Signer {
	account: sr25519::Public,
	block_validation: u32,
}

#[derive(Deserialize, Clone)]
pub struct SecretPacket {
	owner_address: sr25519::Public,

	// Signed by owner
	signer_address: String,
	signersig: String,

	// Signed by signer
	secret_data: String, // TODO: Replace by "SecretData" JWT/JWS
	signature: String,
}

#[derive(Debug, PartialEq)]
pub enum CapsuleOwner {
	Owner(AccountId32),
	NotFound,
}

// Fetch onchain owenrship of nft/capsule id
pub async fn get_capsule_owner(nft_id: u32) -> CapsuleOwner {
	let data = get_capsule_data(nft_id).await;

	let owner = match data {
		Some(capsule_data) => CapsuleOwner::Owner(capsule_data.owner),
		None => CapsuleOwner::NotFound,
	};

	owner
}

pub struct CapsuleStatus {
	/// Is NFT converted to capsule.
	pub is_capsule: bool,
	/// Is NFT listed for sale.
	pub is_listed: bool,
	/// Is NFT contains secret.
	pub is_secret: bool,
	/// Is NFT delegated.
	pub is_delegated: bool,
	/// Is NFT soulbound.
	pub is_soulbound: bool,
	/// Is NFT capsule syncing
	pub is_syncing_capsule: bool,
	/// Is NFT secret syncing
	pub is_syncing_secret: bool,
	/// Is NFT capsule in transmission
	pub is_transmission: bool,
	/// Is NFT Rented or available for rent.
	pub is_rented: bool,
	/// Is NFT available.
	pub is_burnt: bool,
}

// Fetch onchain owenrship of nft/capsule id
pub async fn get_capsule_status(nft_id: u32) -> CapsuleStatus {
	let capsule_data = get_capsule_data(nft_id).await;

	let capsule_state = match capsule_data {
		Some(state) => state,
		None => {
			return CapsuleStatus {
				is_capsule: false,
				is_secret: false,
				is_syncing_secret: false,
				is_syncing_capsule: false,
				is_transmission: false,
				is_delegated: false,
				is_rented: false,
				is_listed: false,
				is_soulbound: false,

				is_burnt: true,
			}
		},
	};

	CapsuleStatus {
		is_capsule: capsule_state.state.is_capsule,
		is_secret: capsule_state.state.is_secret,

		is_syncing_secret: capsule_state.state.is_syncing_secret,
		is_syncing_capsule: capsule_state.state.is_syncing_capsule,

		is_transmission: capsule_state.state.is_transmission,

		is_delegated: capsule_state.state.is_delegated,
		is_rented: capsule_state.state.is_rented,

		is_listed: capsule_state.state.is_listed,
		is_soulbound: capsule_state.state.is_soulbound,
		is_burnt: false,
	}
}

/* ----------------------------------
   SIGNER IMPLEMENTATION
----------------------------------*/

// Check signer account expiration block-number
impl Signer {
	async fn is_valid(self) -> bool {
		self.block_validation > get_current_block_number().await
	}
}

/* ----------------------------------
   SECRET-DATA IMPLEMENTATION
----------------------------------*/

// Retrieving the stored secret
impl SecretData {
	// TODO: use json canonicalization of JOSE/JWT encoder
	fn serialize(self) -> String {
		self.nft_id.to_string() + "_" + &String::from_utf8(self.data).unwrap()
	}

	async fn is_valid(self) -> bool {
		let last_block_number = get_current_block_number().await;
		(last_block_number > self.auth_token.block_number)
			&& (last_block_number < self.auth_token.block_number + self.auth_token.block_validation)
	}
}

/* ----------------------------------
   SECRET-PACKET IMPLEMENTATION
----------------------------------*/

impl SecretPacket {
	fn parse_signer(&self) -> Signer {
		let mut signer = self.signer_address.clone();
		if signer.starts_with("<Bytes>") && signer.ends_with("</Bytes>") {
			signer = signer
				.strip_prefix("<Bytes>")
				.unwrap()
				.strip_suffix("</Bytes>")
				.unwrap()
				.to_string();
		}

		let parsed_signer: Vec<&str> =
			if signer.contains("_") { signer.split("_").collect() } else { vec![&signer] };

		Signer {
			account: sr25519::Public::from_str(parsed_signer[0]).unwrap(),
			block_validation: parsed_signer[1].parse::<u32>().unwrap(),
		}
	}

	// TODO: use json canonicalization of JOSE/JWT decoder
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

		let parsed_data: Vec<&str> = if secret_data.contains("_") {
			secret_data.split("_").collect()
		} else {
			vec![&secret_data]
		};

		SecretData {
			nft_id: parsed_data[0].parse::<u32>().unwrap(),

			data: if !parsed_data[1].is_empty() {
				parsed_data[1].as_bytes().to_vec()
			} else {
				Vec::new()
			},

			auth_token: AuthenticationToken {
				block_number: parsed_data[2].parse::<u32>().unwrap(),
				block_validation: parsed_data[3].parse::<u32>().unwrap(),
			},
		}
	}

	// Owner string to public key
	fn get_owner(&self) -> Result<sr25519::Public, ()> {
		sr25519::Public::from_slice(self.owner_address.clone().as_slice())
	}

	// Signer string to public key
	fn get_signer(&self) -> Result<Signer, ()> {
		let parsed_data: Vec<&str> = if self.signer_address.contains("_") {
			self.signer_address.split("_").collect()
		} else {
			return Err(());
		};
		Ok(Signer {
			account: sr25519::Public::from_str(parsed_data[0]).unwrap(),
			block_validation: parsed_data[1].parse::<u32>().unwrap(),
		})
	}

	// Extract signatures from hex
	fn parse_signature(&self, account: &str) -> Result<sr25519::Signature, SignatureError> {
		let sig = match account {
			"owner" => self.signature.clone(),
			"signer" => self.signersig.clone(),
			_ => return Err(SignatureError::TYPEERROR),
		};

		let strip_sig = match sig.strip_prefix("0x") {
			Some(ssig) => ssig,
			_ => return Err(SignatureError::PREFIXERROR),
		};

		let sig_bytes = match <[u8; 64]>::from_hex(strip_sig) {
			Ok(bsig) => bsig,
			Err(_) => return Err(SignatureError::LENGHTERROR),
		};

		Ok(sr25519::Signature::from_raw(sig_bytes))
	}

	// Verify signatures
	async fn verify_signer(&self) -> Result<bool, VerificationError> {
		let signer = match self.get_signer() {
			Ok(pk) => pk,
			Err(e) => return Err(VerificationError::INVALIDSIGNER),
		};

		let signersig = match self.parse_signature("signer") {
			Ok(sig) => sig,
			Err(e) => return Err(VerificationError::INVALIDSIGNERSIG(e)),
		};

		if signer.is_valid().await {
			let owner = self.get_owner().unwrap();
			let result = sr25519::Pair::verify(&signersig, self.signer_address.clone(), &owner);
			Ok(result)
		} else {
			Err(VerificationError::EXPIREDSIGNER)
		}
	}

	// Verify secret data
	async fn verify_secret(&self) -> Result<bool, VerificationError> {
		let owner = match self.get_owner() {
			Ok(pk) => pk,
			Err(e) => return Err(VerificationError::INVALIDOWNER),
		};

		let signer = self.get_signer().unwrap();

		let packetsig = match self.parse_signature("owner") {
			Ok(sig) => sig,
			Err(e) => {
				return Err(VerificationError::INVALIDOWNERSIG(e));
			},
		};

		let secret = self.parse_secret();
		if secret.is_valid().await {
			let result =
				sr25519::Pair::verify(&packetsig, self.secret_data.clone(), &signer.account);
			Ok(result)
		} else {
			Err(VerificationError::EXPIREDSECRET)
		}
	}

	// Check nft/capsule owner
	async fn check_capsule_ownership(&self) -> bool {
		let capsule_owner = get_capsule_owner(self.parse_secret().nft_id).await;
		match capsule_owner {
			CapsuleOwner::Owner(owner) => owner == self.owner_address.into(),
			CapsuleOwner::NotFound => false,
		}
	}

	async fn verify_request(&self) -> Result<SecretData, VerificationError> {
		match self.verify_signer().await {
			Ok(true) => match self.check_capsule_ownership().await {
				true => match self.verify_secret().await {
					Ok(true) => Ok(self.parse_secret()),
					Ok(false) => Err(VerificationError::OWNERVERIFICATIONFAILED),
					Err(e) => Err(e),
				},

				false => Err(VerificationError::INVALIDOWNER),
			},

			Ok(false) => Err(VerificationError::SIGNERVERIFICATIONFAILED),
			Err(e) => Err(e),
		}
	}
}

/* **********************
   SECRET AVAILABLE API
********************** */
#[derive(Serialize)]
pub struct CapsuleExistsResponse {
	enclave_id: String,
	nft_id: u32,
	exists: bool,
}

pub async fn capsule_is_available(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let file_path = state.seal_path + "capsule_" + &nft_id.to_string() + ".secret";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Availability check : path checked, path: {}", file_path);
		return (
			StatusCode::OK,
			Json(CapsuleExistsResponse { enclave_id: state.identity, nft_id, exists: true }),
		);
	} else {
		info!(
			"Availability check : secret does not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::OK,
			Json(CapsuleExistsResponse { enclave_id: state.identity, nft_id, exists: false }),
		);
	};
}

/* **********************
	 SECRET VIEW API
********************** */

#[derive(Serialize)]
pub struct CapsuleViewResponse {
	enclave_id: String,
	nft_id: u32,
	log: String,
}

// TODO: check the request for signed data and prevent flooding requests.
pub async fn capsule_get_views_handler(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let file_path = state.seal_path + "capsule_" + &nft_id.to_string() + ".log";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Log path checked, path: {}", file_path);
	} else {
		error!(
			"Error retrieving secret log : log path does not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::OK,
			Json(CapsuleViewResponse {
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
				Json(CapsuleViewResponse {
					enclave_id: state.identity,
					nft_id,
					log: "can not retrieve the log of capsule views".to_string(),
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
				Json(CapsuleViewResponse { enclave_id: state.identity, nft_id, log: log_data }),
			);
		},

		Err(_) => {
			error!(
				"Error retrieving secret log : can not read the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::OK,
				Json(CapsuleViewResponse {
					enclave_id: state.identity,
					nft_id,
					log: "can not retrieve the log of capsule views".to_string(),
				}),
			);
		},
	};
}

/* **********************
	 STORE SECRET
********************** */
#[derive(Serialize)]
pub struct SecretStoreResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

pub async fn capsule_store_secret_shares(
	State(state): State<StateConfig>,
	Json(received_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_secret = received_secret.verify_request().await;

	match verified_secret {
		Ok(secret) => {
			if std::path::Path::new(&state.clone().seal_path).exists() {
				info!("Seal path checked, path: {}", state.seal_path.clone());
			} else {
				error!("Error storing secrets to TEE : seal path does not exist, nft_id : {}, path : {}", secret.nft_id, state.seal_path);

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

			let file_path =
				state.seal_path.clone() + "capsule_" + &secret.nft_id.to_string() + ".secret";
			let exist = std::path::Path::new(file_path.as_str()).exists();

			if exist {
				warn!(
					"Error storing secrets to TEE : nft_id already exists, nft_id = {}",
					secret.nft_id
				);

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::CAPSULEIDEXISTS,
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
					secret.nft_id, received_secret.owner_address
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

			// Send extrinsic to Secret-Capsule Pallet as Storage-Oracle
			match capsule_secret_share_oracle(state.enclave_key.clone(), secret.nft_id).await {
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to secret-capsule-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
						secret.nft_id, received_secret.owner_address, txh
					);

					// Log file for tracing the secrets VIEW history in Marketplace.
					let file_path =
						state.seal_path + "capsule_" + &secret.nft_id.to_string() + ".log";
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
			VerificationError::INVALIDSIGNERSIG(e) => {
				warn!("Error storing secrets to TEE : Invalid Request Signature");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Invalid Signer Signature"
							.to_string(),
					}),
				);
			},

			VerificationError::INVALIDOWNERSIG(e) => {
				warn!("Error storing secrets to TEE : Invalid Request Signature");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::INVALIDOWNERSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Invalid Request Signature"
							.to_string(),
					}),
				);
			},

			VerificationError::INVALIDOWNER => {
				warn!("Error storing secrets to TEE : Invalid Capsule Owner");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::INVALIDOWNER,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Invalid Capsule Owner"
							.to_string(),
					}),
				);
			},

			VerificationError::SIGNERVERIFICATIONFAILED => todo!(),
			VerificationError::OWNERVERIFICATIONFAILED => todo!(),
			VerificationError::INVALIDSIGNER => todo!(),
			VerificationError::EXPIREDSIGNER => todo!(),
			VerificationError::EXPIREDSECRET => todo!(),
		},
	}
}

/* **********************
	 RETRIEVE SECRET
********************** */

#[derive(Serialize)]
pub struct SecretRetrieveResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	secret_data: String,
	description: String,
}

pub async fn capsule_retrieve_secret_shares(
	State(state): State<StateConfig>,
	Json(requested_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_req = requested_secret.verify_request().await;

	match verified_req {
		Ok(data) => {
			let file_path =
				state.seal_path.clone() + "capsule_" + &data.nft_id.to_string() + ".secret";
			if !std::path::Path::new(&file_path).is_file() {
				warn!(
					"Error retrieving secrets from TEE : file path does not exist, file_path : {}",
					file_path
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::CAPSULEIDNOTEXIST,
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
							status: ReturnStatus::CAPSULESECRETNOTACCESSIBLE,
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

			let mut capsule_secret_share = Vec::<u8>::new();

			match file.read_to_end(&mut capsule_secret_share) {
				Ok(_) => info!(
					"Secret shares of {} retrieved by {}",
					data.nft_id, requested_secret.owner_address
				),

				Err(err) => {
					error!("Error retrieving secrets from TEE : can not read secret file, nft_id : {} Error : {}", data.nft_id, err);

					return (
						StatusCode::OK,
						Json(SecretRetrieveResponse {
							status: ReturnStatus::CAPSULESECRETNOTREADABLE,
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
			let file_path = state.seal_path + "capsule_" + &data.nft_id.to_string() + ".log";
			let mut log_file = OpenOptions::new()
				.append(true)
				.open(file_path)
				.expect("Unable to open log file");

			log_file.seek(std::io::SeekFrom::End(0)).unwrap();

			let time: chrono::DateTime<chrono::offset::Utc> = std::time::SystemTime::now().into();
			let log_data = requested_secret.owner_address.to_string()
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
					secret_data: SecretData {
						nft_id: data.nft_id,
						data: capsule_secret_share,
						auth_token: AuthenticationToken { block_number: get_current_block_number().await, block_validation: 100 },
					}
					.serialize(),
				}),
			);
		},

		Err(err) => match err {
			VerificationError::INVALIDOWNERSIG(e) => {
				info!(
					"Error retrieving secrets from TEE : Invalid Signature, owner : {}",
					requested_secret.owner_address
				);

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNERSIGNATURE,
						nft_id: 0,
						enclave_id: state.identity,
						description: "Error Invalid Signature or Capsule owner".to_string(),
						secret_data: SecretData {
							nft_id: 0,
							data: Vec::new(),
							auth_token: AuthenticationToken { block_number: get_current_block_number().await, block_validation: 100 },
						}
						.serialize(),
					}),
				);
			},

			VerificationError::INVALIDOWNER => {
				info!(
					"Error retrieving secrets from TEE : Invalid Owner, owner : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						nft_id: 0,
						enclave_id: state.identity,
						description: "Error Invalid Capsule owner".to_string(),
						secret_data: SecretData {
							nft_id: 0,
							data: Vec::new(),
							auth_token: AuthenticationToken { block_number: get_current_block_number().await, block_validation: 100 },
						}
						.serialize(),
					}),
				);
			},
			VerificationError::INVALIDSIGNERSIG(_) => todo!(),
			VerificationError::SIGNERVERIFICATIONFAILED => todo!(),
			VerificationError::OWNERVERIFICATIONFAILED => todo!(),
			VerificationError::INVALIDSIGNER => todo!(),
			VerificationError::EXPIREDSIGNER => todo!(),
			VerificationError::EXPIREDSECRET => todo!(),
		},
	}
}

/* **********************
	 CHANGE SECRET
********************** */
#[derive(Serialize)]
pub struct SecretChangeResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

pub async fn capsule_change_secret_shares(
	State(state): State<StateConfig>,
	Json(change_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_req = change_secret.verify_request().await;
	match verified_req {
		Ok(secret) => {
			// Check if is_syncing_secret == true or is_syncing_capsule == true
			let status = get_capsule_status(secret.nft_id).await;
			if status.is_syncing_capsule || status.is_syncing_secret {
				if std::path::Path::new(&state.clone().seal_path).exists() {
					info!("Seal path checked, path: {}", state.seal_path.clone());
				} else {
					error!("Error storing secrets to TEE : seal path does not exist, nft_id : {}, path : {}", secret.nft_id, state.seal_path);

					return (
						StatusCode::OK,
						Json(SecretChangeResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description:
								"Error storing secrets to TEE, use another enclave please."
									.to_string(),
						}),
					);
				};

				let file_path =
					state.seal_path.clone() + "capsule_" + &secret.nft_id.to_string() + ".secret";
				let exist = std::path::Path::new(file_path.as_str()).exists();

				if !exist {
					warn!(
						"Error storing secrets to TEE : nft_id does not exist, nft_id = {}",
						secret.nft_id
					);

					return (
						StatusCode::OK,
						Json(SecretChangeResponse {
							status: ReturnStatus::CAPSULEIDEXISTS,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description: "Error storing secrets to TEE : nft_id does not exist"
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
							Json(SecretChangeResponse {
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
						secret.nft_id, change_secret.owner_address
					),
					Err(err) => {
						error!("Error storing secrets to TEE : error in writing data to file, nft_id : {}, path: {}, Error : {}", secret.nft_id, file_path, err);

						return (
							StatusCode::OK,
							Json(SecretChangeResponse {
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

				// Send extrinsic to Secret-Capsule Pallet as Storage-Oracle
				match capsule_secret_share_oracle(state.enclave_key.clone(), secret.nft_id).await {
					Ok(txh) => {
						info!(
							"Proof of storage has been sent to secret-capsule-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
							secret.nft_id, change_secret.owner_address, txh
						);

						// Log file for tracing the secrets VIEW history in Marketplace.
						let file_path =
							state.seal_path + "capsule_" + &secret.nft_id.to_string() + ".log";
						std::fs::File::create(file_path.clone()).unwrap();

						return (
							StatusCode::OK,
							Json(SecretChangeResponse {
								status: ReturnStatus::SECRETCHANGED,
								nft_id: secret.nft_id,
								enclave_id: state.identity,
								description: "Secret ia successfully changed in enclave."
									.to_string(),
							}),
						);
					},

					Err(err) => {
						error!(
							"Error sending proof of storage to chain, nft_id : {}, Error : {}",
							secret.nft_id, err
						);

						std::fs::remove_file(file_path.clone())
							.expect("Can not remove secret file");

						return (
							StatusCode::OK,
							Json(SecretChangeResponse {
								status: ReturnStatus::ORACLEFAILURE,
								nft_id: secret.nft_id,
								enclave_id: state.identity,
								description: "Error sending proof of storage to chain.".to_string(),
							}),
						);
					},
				}
			} else {
				return (
					StatusCode::OK,
					Json(SecretChangeResponse {
						status: ReturnStatus::CAPSULENOTSYNCING,
						nft_id: secret.nft_id,
						enclave_id: state.identity,
						description: "Capsule is not in syncing state.".to_string(),
					}),
				);
			}
		},
		Err(_) => todo!(),
	}
}

/* **********************
	 REMOVE SECRET
********************** */
#[derive(Serialize)]
pub struct SecretRemoveResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

pub async fn capsule_remove_secret_shares(
	State(state): State<StateConfig>,
	Json(remove_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_req = remove_secret.verify_request().await;
	match verified_req {
		Ok(secret) => {
			// Check if NFT/CAPSULE is burnt
			let status = get_capsule_status(secret.nft_id).await;
			if status.is_burnt {
				if std::path::Path::new(&state.clone().seal_path).exists() {
					info!("Seal path checked, path: {}", state.seal_path.clone());
				} else {
					error!("Error removing secrets to TEE : seal path does not exist, nft_id : {}, path : {}", secret.nft_id, state.seal_path);

					return (
						StatusCode::OK,
						Json(SecretRemoveResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description:
								"Error storing secrets to TEE, use another enclave please."
									.to_string(),
						}),
					);
				};

				let file_path =
					state.seal_path.clone() + "capsule_" + &secret.nft_id.to_string() + ".secret";
				let exist = std::path::Path::new(file_path.as_str()).exists();

				if !exist {
					warn!(
						"Error storing secrets to TEE : nft_id does not exist, nft_id = {}",
						secret.nft_id
					);

					return (
						StatusCode::OK,
						Json(SecretRemoveResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description: "Error removing secrets from TEE : nft_id does not exist"
								.to_string(),
						}),
					);
				}

				let mut f = match std::fs::remove_file(file_path.clone()) {
					Ok(file) => return (
						StatusCode::OK,
						Json(SecretRemoveResponse {
							status: ReturnStatus::SECRETREMOVED,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description: "Secret ia successfully removed from enclave.".to_string(),
						}),
					),
					
					Err(err) => {
						error!("Error removing secrets from TEE : error in removing file on disk, nft_id : {}, path : {}, Error : {}", secret.nft_id, file_path, err);

						return (
							StatusCode::OK,
							Json(SecretRemoveResponse {
								status: ReturnStatus::DATABASEFAILURE,
								nft_id: secret.nft_id,
								enclave_id: state.identity,
								description:
									"Error removing secrets from TEE, try again or contact cluster admin please."
										.to_string(),
							}),
						);
					},
				};
			} else {
				return (
					StatusCode::OK,
					Json(SecretRemoveResponse {
						status: ReturnStatus::CAPSULENOTBURNT,
						nft_id: secret.nft_id,
						enclave_id: state.identity,
						description:
							"Error removing secrets from TEE, Capsule is not in burnt state."
								.to_string(),
					}),
				);
			}
		},

		Err(_) => todo!(),
	}
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;
	use sp_keyring::AccountKeyring;

	/* TODO: This test can not pass in workflow action, without verified account and nft_id
	#[tokio::test]
	async fn get_capsule_owner_test() {
		let address = AccountId32::from(
			sr25519::Public::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6")
				.unwrap(),
		);
		let nft_id = 10;
		let owner = match get_capsule_owner(nft_id).await {
			CapsuleOwner::Owner(addr) => addr,
			CapsuleOwner::NotFound => panic!("Test erros, nft_id is not available, check your chain."),
		};
		let other = match get_capsule_owner(nft_id + 100).await {
			CapsuleOwner::Owner(addr) => addr,
			CapsuleOwner::NotFound => panic!("Test erros, nft_id is not available, check your chain."),
		};
		let unknown = get_capsule_owner(10_000).await;

		assert_eq!(owner, address); // Same Capsule match Owner
		assert_ne!(other, address); // Different Capsules, (probably) diffetent owners
		assert_ne!(owner, AccountKeyring::Alice.to_raw_public().into()); // Unauthorized random owner
		assert_eq!(unknown, CapsuleOwner::NotFound); // Unavailable Capsule
	}
	*/
	#[tokio::test]
	async fn parse_secret_from_sdk_test() {
		let secret_packet_sdk: SecretPacket = SecretPacket {
			owner_address: sr25519::Public::from_slice(&[0u8;32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8;32]).unwrap().to_string(),
			secret_data: "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
			signersig: "xxx".to_string(),
		};

		// Signed in SDK
		let secret_data = secret_packet_sdk.parse_secret();

		assert_eq!(secret_data.nft_id, 10);
		assert_eq!(secret_data.data, b"CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU");
	}

	#[tokio::test]
	async fn parse_secret_from_polkadotjs_test() {
		let secret_packet_polkadotjs:SecretPacket = SecretPacket {
			owner_address: sr25519::Public::from_slice(&[0u8;32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8;32]).unwrap().to_string(),
			secret_data: "<Bytes>247_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU</Bytes>".to_string(), 
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};
		// Signed in Polkadot.JS
		let secret_data = secret_packet_polkadotjs.parse_secret();

		assert_eq!(secret_data.nft_id, 247);
		assert_eq!(secret_data.data, b"CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU");
	}

	#[tokio::test]
	async fn get_public_key_test() {
		let secret_packet_sdk: SecretPacket = SecretPacket {
			owner_address: <sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check(
				"5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6",
			)
			.unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			secret_data: "xxx".to_string(),
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};

		let pk = secret_packet_sdk.get_owner().unwrap();

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
			owner_address: sr25519::Public::from_slice(&[0u8;32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8;32]).unwrap().to_string(),
			secret_data: "xxx".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
			signersig: "xxx".to_string(),
		};

		let sig = secret_packet_sdk.parse_signature("owner").unwrap();
		assert_eq!(sig, correct_sig);

		// 0x prefix
		secret_packet_sdk.signature = "42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		let sig = secret_packet_sdk.parse_signature("owner").unwrap_err();
		assert_eq!(sig, SignatureError::PREFIXERROR);

		// Length
		secret_packet_sdk.signature = "0x2bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		let sig = secret_packet_sdk.parse_signature("owner").unwrap_err();
		assert_eq!(sig, SignatureError::LENGHTERROR);
	}

	#[tokio::test]
	async fn verify_signature_test() {
		let mut secret_packet = SecretPacket {
			owner_address: <sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6").unwrap(),
			signer_address: <sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6").unwrap().to_string(),
			secret_data: "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
			signersig: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
		};

		assert_eq!(secret_packet.verify_secret().await.unwrap(), true);

		// changed secret
		secret_packet.secret_data = "10_DAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string();
		assert_eq!(secret_packet.verify_secret().await.unwrap(), false);

		// changed owner
		secret_packet.owner_address =
			sr25519::Public::from_slice(&AccountKeyring::Alice.to_raw_public()).unwrap();
		secret_packet.secret_data = "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string();
		assert_eq!(secret_packet.verify_secret().await.unwrap(), false);

		// changed signature
		secret_packet.owner_address =
			<sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check(
				"5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6",
			)
			.unwrap();
		secret_packet.signature = "0x32bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		assert_eq!(secret_packet.verify_secret().await.unwrap(), false);
	}

	async fn full_verify_received_data_test() {
		let secret_packet = SecretPacket {
			owner_address: <sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6").unwrap(),
			signer_address: <sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6").unwrap().to_string(),
			secret_data: "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
			signersig: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
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
			&sr25519::Public::from_slice(&secret_packet.owner_address.as_slice()).unwrap(), /* public1 */
		);
		let vr2 = sr25519::Pair::verify(&signature2, message2, &public2);

		info!("res1 : {}\nres2 : {}", vr1, vr2);

		match secret_packet.verify_request().await {
			Ok(_) => info!("Secret is Valid!"),

			Err(err) => match err {
				VerificationError::INVALIDOWNERSIG(e) => info!("Signature Error!"),

				VerificationError::INVALIDOWNER => info!("Invalid Owner!"),

				VerificationError::INVALIDSIGNERSIG(_) => todo!(),
				VerificationError::SIGNERVERIFICATIONFAILED => todo!(),
				VerificationError::OWNERVERIFICATIONFAILED => todo!(),
				VerificationError::INVALIDSIGNER => todo!(),
				VerificationError::EXPIREDSIGNER => todo!(),
				VerificationError::EXPIREDSECRET => todo!(),
			},
		}
	}
}
