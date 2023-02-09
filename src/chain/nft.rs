use crate::servers::http_server::StateConfig;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use tracing::{error, info, warn};

use axum::extract::Path as PathExtract;

use crate::chain::chain::{get_current_block_number, nft_secret_share_oracle};
use crate::chain::verify::*;
use serde::Serialize;

/* **********************
   SECRET AVAILABLE API
********************** */
#[derive(Serialize)]
pub struct NFTExistsResponse {
	enclave_id: String,
	nft_id: u32,
	exists: bool,
}

pub async fn is_nft_available(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let file_path = state.seal_path + "nft_" + &nft_id.to_string() + ".secret";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Availability check : path checked, path: {}", file_path);
		return (
			StatusCode::OK,
			Json(NFTExistsResponse { enclave_id: state.identity, nft_id, exists: true }),
		);
	} else {
		info!(
			"Availability check : secret does not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::OK,
			Json(NFTExistsResponse { enclave_id: state.identity, nft_id, exists: false }),
		);
	};
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
pub async fn nft_get_views_handler(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let file_path = state.seal_path + "nft_" + &nft_id.to_string() + ".log";

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
#[derive(Serialize)]
pub struct SecretStoreResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

pub async fn nft_store_secret_shares(
	State(state): State<StateConfig>,
	Json(received_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_secret = received_secret.verify_request().await;

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

			let file_path =
				state.seal_path.clone() + "nft_" + &secret.nft_id.to_string() + ".secret";
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

			// Send extrinsic to Secret-NFT Pallet as Storage-Oracle
			match nft_secret_share_oracle(state.enclave_key.clone(), secret.nft_id).await {
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to secret-nft-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
						secret.nft_id, received_secret.owner_address, txh
					);

					// Log file for tracing the secrets VIEW history in Marketplace.
					let file_path = state.seal_path + "nft_" + &secret.nft_id.to_string() + ".log";
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
				warn!("Error storing secrets to TEE : Invalid Request Signature, {:?}", e);

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Invalid Request Signature"
							.to_string(),
					}),
				);
			},

			VerificationError::INVALIDOWNER => {
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

			VerificationError::INVALIDOWNERSIG(e) => {
				warn!("Error storing secrets to TEE : Request signature is invalid. {:?}", e);

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::EXPIREDSIGNER,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Request signature is invalid."
							.to_string(),
					}),
				);
			},

			VerificationError::SIGNERVERIFICATIONFAILED => {
				warn!("Error storing secrets to TEE : Signer verification failed.");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Signer verification failed."
							.to_string(),
					}),
				);
			},

			VerificationError::OWNERVERIFICATIONFAILED => {
				warn!("Error storing secrets to TEE : Ownership validation failed.");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::EXPIREDSIGNER,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Ownership validation failed."
							.to_string(),
					}),
				);
			},

			VerificationError::INVALIDSIGNERACCOUNT => {
				warn!("Error storing secrets to TEE : Signer account is invalid.");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Signer account is invalid."
							.to_string(),
					}),
				);
			},

			VerificationError::EXPIREDSIGNER => {
				warn!("Error storing secrets to TEE : Signer account is expired.");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::EXPIREDSIGNER,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Signer account is expired."
							.to_string(),
					}),
				);
			},

			VerificationError::EXPIREDSECRET => {
				warn!("Error storing secrets to TEE : Secret request is expired.");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: ReturnStatus::EXPIREDREQUEST,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error storing secrets to TEE : Secret request is expired."
							.to_string(),
					}),
				);
			},
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

pub async fn nft_retrieve_secret_shares(
	State(state): State<StateConfig>,
	Json(requested_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_req = requested_secret.verify_request().await;

	match verified_req {
		Ok(data) => {
			let file_path = state.seal_path.clone() + "nft_" + &data.nft_id.to_string() + ".secret";
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
					data.nft_id, requested_secret.owner_address
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
			let file_path = state.seal_path + "nft_" + &data.nft_id.to_string() + ".log";
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
						data: nft_secret_share,
						auth_token: AuthenticationToken {
							block_number: get_current_block_number().await,
							block_validation: 100,
						},
					}
					.serialize(),
				}),
			);
		},

		Err(err) => match err {
			VerificationError::INVALIDSIGNERSIG(e) => {
				warn!("Error retrieving secrets from TEE : Invalid Request Signature, {:?}", e);

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: requested_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description:
							"Error retrieving secrets from TEE : Invalid Request Signature"
								.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			},

			VerificationError::INVALIDOWNER => {
				warn!("Error retrieving secrets from TEE : Invalid NFT Owner");

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						nft_id: requested_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error retrieving secrets from TEE : Invalid NFT Owner"
							.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			},

			VerificationError::INVALIDOWNERSIG(e) => {
				warn!("Error retrieving secrets from TEE : Request signature is invalid. {:?}", e);

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::EXPIREDSIGNER,
						nft_id: requested_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description:
							"Error retrieving secrets from TEE : Request signature is invalid."
								.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			},

			VerificationError::SIGNERVERIFICATIONFAILED => {
				warn!("Error retrieving secrets from TEE : Signer verification failed.");

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: requested_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description:
							"Error retrieving secrets from TEE : Signer verification failed."
								.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			},

			VerificationError::OWNERVERIFICATIONFAILED => {
				warn!("Error retrieving secrets from TEE : Ownership validation failed.");

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						nft_id: requested_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description:
							"Error retrieving secrets from TEE : Ownership validation failed."
								.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			},

			VerificationError::INVALIDSIGNERACCOUNT => {
				warn!("Error retrieving secrets from TEE : Signer account is invalid.");

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: requested_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description:
							"Error retrieving secrets from TEE : Signer account is invalid."
								.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			},

			VerificationError::EXPIREDSIGNER => {
				warn!("Error retrieving secrets from TEE : Signer account is expired.");

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::EXPIREDSIGNER,
						nft_id: requested_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description:
							"Error retrieving secrets from TEE : Signer account is expired."
								.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			},

			VerificationError::EXPIREDSECRET => {
				warn!("Error retrieving secrets from TEE : Secret request is expired.");

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::EXPIREDREQUEST,
						nft_id: requested_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description:
							"Error retrieving secrets from TEE : Secret request is expired."
								.to_string(),
						secret_data: "_".to_string(),
					}),
				);
			},
		},
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

pub async fn nft_remove_secret_shares(
	State(state): State<StateConfig>,
	Json(remove_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_req = remove_secret.verify_request().await;
	match verified_req {
		Ok(secret) => {
			// Check if NFT/CAPSULE is burnt
			let status = get_onchain_status(secret.nft_id).await;
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
					state.seal_path.clone() + "nft_" + &secret.nft_id.to_string() + ".secret";
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

				match std::fs::remove_file(file_path.clone()) {
					Ok(_) => {
						return (
							StatusCode::OK,
							Json(SecretRemoveResponse {
								status: ReturnStatus::REMOVESUCCESS,
								nft_id: secret.nft_id,
								enclave_id: state.identity,
								description: "Secret ia successfully removed from enclave."
									.to_string(),
							}),
						)
					},

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
						status: ReturnStatus::NFTNOTBURNT,
						nft_id: secret.nft_id,
						enclave_id: state.identity,
						description: "Error removing secrets from TEE, NFT is not in burnt state."
							.to_string(),
					}),
				);
			}
		},

		Err(_) => todo!(),
	}
}
