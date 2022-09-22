use crate::chain::chain::get_nft_data;
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse, Json};
use std::io::{Read, Write};

use subxt::ext::{
	sp_core::{sr25519, ByteArray, Pair},
	sp_runtime::AccountId32,
};
//use crate::chain::chain::ternoa::runtime_types::sp_core::crypto::AccountId32;

//use subxt::ext::sp_core::crypto::Ss58C&&odec;

use serde::{Deserialize, Serialize};

const NFT_DIR_PATH: &str = "./credentials/nft/";

#[derive(Debug)]
pub enum SecretError {
	DecodeError,
	SignatureInvalid,
	OwnerInvalid,
}

#[derive(Deserialize, Clone)]
pub struct SecretPacket {
	account_address: AccountId32,
	secret_data: SecretData,
	signature: sr25519::Signature,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretData {
	nft_id: u32,
	data: Vec<u8>,
}

#[derive(Serialize)]
pub struct SecretStoreResponse {
	status: u32,
	nft_id: u32,
	cluster_id: u32,
	description: String,
}

#[derive(Serialize)]
pub struct SecretRetrieveResponse {
	status: u32,
	nft_id: u32,
	cluster_id: u32,
	secret_data: SecretData,
}

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

#[async_trait]
pub trait VerifyNFT {
	fn get_public_key(&self) -> sr25519::Public;
	fn verify_signature(&self) -> bool;
	async fn check_nft_ownership(&self) -> bool;
	async fn verify_receive_data(&self) -> Result<SecretData, SecretError>;
}

#[async_trait]
impl VerifyNFT for SecretPacket {
	fn get_public_key(&self) -> sr25519::Public {
		sr25519::Public::from_slice(self.account_address.clone().as_slice()).expect("Valid address")
	}

	fn verify_signature(&self) -> bool {
		let account_pubkey = self.get_public_key();
		let encoded: Vec<u8> = bincode::serialize(&self.secret_data).unwrap();
		sr25519::Pair::verify(&self.signature.clone(), encoded, &account_pubkey)
	}

	async fn check_nft_ownership(&self) -> bool {
		let nft_owner = get_nft_owner(self.secret_data.nft_id).await;
		match nft_owner {
			NFTOwner::Owner(owner) => owner == self.account_address,
			NFTOwner::NotFound => false,
		}
	}

	async fn verify_receive_data(&self) -> Result<SecretData, SecretError> {
		if self.verify_signature() {
			if self.check_nft_ownership().await {
				Ok(self.secret_data.clone())
			} else {
				Err(SecretError::OwnerInvalid)
			}
		} else {
			Err(SecretError::SignatureInvalid)
		}
	}
}

/* STORE SECRET */

pub async fn store_secret_shares(Json(received_secret): Json<SecretPacket>) -> impl IntoResponse {
	let verified_secret = received_secret.verify_receive_data().await;

	match verified_secret {
		Ok(secret) => {
			std::fs::create_dir_all(NFT_DIR_PATH).unwrap();
			let file_path = NFT_DIR_PATH.to_owned() + &secret.nft_id.to_string() + ".secret";

			let mut f = match std::fs::File::create(file_path) {
				Ok(file) => file,
				Err(err) => {
					println!("Error storing secrets to TEE : nft_id already exists, nft_id = {}, Error = {}", secret.nft_id, err);

					return (
						StatusCode::OK,
						Json(SecretStoreResponse {
							status: 411,
							nft_id: secret.nft_id,
							cluster_id: 1,
							description: "Error storing secrets to TEE : nft_id already exists, file creation error"
								.to_string(),
						}),
					);
				},
			};

			f.write_all(&secret.data).unwrap();

			println!(
				"Secret is successfully stored to TEE, nft_id = {} by Owner = {}",
				secret.nft_id, received_secret.account_address
			);

			return (
				StatusCode::OK,
				Json(SecretStoreResponse {
					status: 200,
					nft_id: secret.nft_id,
					cluster_id: 1,
					description: "Secret is successfully stored to TEE".to_string(),
				}),
			);
		},

		Err(err) => match err {
			SecretError::SignatureInvalid => {
				println!("Error storing secrets to TEE : Invalid Request Signature");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: 412,
						nft_id: received_secret.secret_data.nft_id,
						cluster_id: 1,
						description: "Error storing secrets to TEE : Invalid Request Signature"
							.to_string(),
					}),
				);
			},

			SecretError::OwnerInvalid => {
				println!("Error storing secrets to TEE : Invalid NFT Owner");

				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: 413,
						nft_id: received_secret.secret_data.nft_id,
						cluster_id: 1,
						description: "Error storing secrets to TEE : Invalid NFT Owner".to_string(),
					}),
				);
			},

			SecretError::DecodeError => {
				return (
					StatusCode::OK,
					Json(SecretStoreResponse {
						status: 414,
						nft_id: 0,
						cluster_id: 1,
						description: "Error storing secrets to TEE : nonparsable payload"
							.to_string(),
					}),
				)
			},
		},
	}
}

/* RETRIEVE SECRET */
pub async fn retrieve_secret_shares(
	Json(requested_secret): Json<SecretPacket>,
) -> impl IntoResponse {
	let verified_req = requested_secret.verify_receive_data().await;

	match verified_req {
		Ok(data) => {
			let file_path = NFT_DIR_PATH.to_owned() + &data.nft_id.to_string() + ".secret";
			if !std::path::Path::new(&file_path).is_file() {
				println!(
					"Error retrieving secrets from TEE : file path does not exist, file_path : {}",
					file_path
				);
				return (
					StatusCode::UNPROCESSABLE_ENTITY,
					Json(SecretRetrieveResponse {
						status: 410,
						nft_id: 0,
						cluster_id: 1,
						secret_data: SecretData {
							nft_id: 0,
							data: "Error retrieving secrets from TEE : nft_id does not exist"
								.as_bytes()
								.to_vec(),
						},
					}),
				);
			}

			let mut file =
				match std::fs::File::open(file_path) {
					Ok(file) => file,
					Err(_) => {
						println!("Error retrieving secrets from TEE : nft_id does not exist, nft_id : {}", data.nft_id );

						return (
							StatusCode::UNPROCESSABLE_ENTITY,
							Json(SecretRetrieveResponse {
								status: 420,
								nft_id: 0,
								cluster_id: 1,
								secret_data: SecretData {
									nft_id: 0,
									data:
										"Error retrieving secrets from TEE : nft_id does not exist"
											.as_bytes()
											.to_vec(),
								},
							}),
						);
					},
				};

			let mut nft_secret_share = Vec::<u8>::new();

			file.read_to_end(&mut nft_secret_share).unwrap();

			println!(
				"Secret shares of {} retrieved by {}",
				data.nft_id, requested_secret.account_address
			);

			return (
				StatusCode::OK,
				Json(SecretRetrieveResponse {
					status: 200,
					nft_id: data.nft_id,
					cluster_id: 1,
					secret_data: SecretData { nft_id: data.nft_id, data: nft_secret_share },
				}),
			);
		},

		Err(err) => match err {
			SecretError::DecodeError => {
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: 415,
						nft_id: 0,
						cluster_id: 1,
						secret_data: SecretData {
							nft_id: 0,
							data: "Error payload is not parsable".as_bytes().to_vec(),
						},
					}),
				)
			},
			SecretError::SignatureInvalid => {
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: 416,
						nft_id: 0,
						cluster_id: 1,
						secret_data: SecretData {
							nft_id: 0,
							data: "Error Invalid Signature or NFT owner".as_bytes().to_vec(),
						},
					}),
				)
			},
			SecretError::OwnerInvalid => {
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: 417,
						nft_id: 0,
						cluster_id: 1,
						secret_data: SecretData {
							nft_id: 0,
							data: "Error Invalid Signature or NFT owner".as_bytes().to_vec(),
						},
					}),
				)
			},
		},
	}
}

/* TEST */
#[cfg(test)]
mod test {
	use super::*;
	use bincode::serialize;
	//use hex_literal::hex;
	use subxt::ext::sp_runtime::app_crypto::Ss58Codec;

	#[tokio::test]
	async fn verification_test() {
		/*
		Secret phrase `pulse roof remain feel system fabric wolf travel intact patrol chest carbon` is account:
		Secret seed:       0x7376f932ed87cefd1595709c6a2e3a10511b9e643723e65aead3ef1620c8d0b7
		Public key (hex):  0x1c4a6fe4fe51c00cd8b5948a143f055b789050b99fd28d95095b542dd122370c
		Public key (SS58): 5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET
		Account ID:        0x1c4a6fe4fe51c00cd8b5948a143f055b789050b99fd28d95095b542dd122370c
		SS58 Address:      5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET
		*/

		/*
		let kp = sr25519::Pair::from_seed(&hex!(
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
		));

		let public = kp.public();
		*/

		let (kp, _) = sr25519::Pair::from_string_with_seed(
			"pulse roof remain feel system fabric wolf travel intact patrol chest carbon",
			None,
		)
		.unwrap();

		let sd = SecretData { nft_id: 48384, data: "This is a share of 5 shares!".into() };

		let ser_sd: Vec<u8> = serialize(&sd).unwrap();
		println!("serialized secure data = {:-?}", ser_sd);

		let sp = SecretPacket {
			//account_address: AccountId32::from(public),
			account_address: AccountId32::from_ss58check(
				"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET",
			)
			.unwrap(),
			secret_data: sd.clone(),
			signature: kp.sign(&ser_sd),
		};

		println!("signature = {:-?}", kp.sign(&ser_sd));

		match sp.verify_receive_data().await {
			Ok(_) => println!("Secret is Valid!"),

			Err(err) => match err {
				SecretError::SignatureInvalid => println!("Signature Error!"),

				SecretError::OwnerInvalid => println!("Invalid Owner!"),

				SecretError::DecodeError => println!("Decode Error"),
			},
		}
	}
}
