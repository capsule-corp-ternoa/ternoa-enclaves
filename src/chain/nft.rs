use crate::chain::chain::get_nft_data;
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse, Json};
use hex::{FromHex, ToHex};
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
	secret_data: String,
	signature: String,
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
	secret_data: String,
	description: String,
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
		let secret_data = self.secret_data.clone();
		let secret_data =
			secret_data.strip_prefix("<Bytes>").unwrap().strip_suffix("</Bytes>").unwrap();
		let nftid_data: Vec<&str> = secret_data.split("_").collect();
		SecretData {
			nft_id: nftid_data[0].parse::<u32>().unwrap(),
			data: nftid_data[1].as_bytes().to_vec(),
		}
	}
}

#[async_trait]
pub trait VerifyNFT {
	fn get_public_key(&self) -> sr25519::Public;
	fn parse_signature(&self) -> sr25519::Signature;
	fn verify_signature(&self) -> bool;
	async fn check_nft_ownership(&self) -> bool;
	async fn verify_receive_data(&self) -> Result<SecretData, SecretError>;
}

#[async_trait]
impl VerifyNFT for SecretPacket {
	fn get_public_key(&self) -> sr25519::Public {
		sr25519::Public::from_slice(self.account_address.clone().as_slice()).expect("Valid address")
	}

	fn parse_signature(&self) -> sr25519::Signature {
		let sig_bytes = <[u8; 64]>::from_hex(self.signature.strip_prefix("0x").unwrap()).unwrap();
		sr25519::Signature::from_raw(sig_bytes)
	}

	fn verify_signature(&self) -> bool {
		let account_pubkey = self.get_public_key();
		//let encoded: Vec<u8> = bincode::serialize(&self.secret_data).unwrap();
		sr25519::Pair::verify(&self.parse_signature(), self.secret_data.clone(), &account_pubkey)
	}

	async fn check_nft_ownership(&self) -> bool {
		let nft_owner = get_nft_owner(self.parse_secret().nft_id).await;
		match nft_owner {
			NFTOwner::Owner(owner) => owner == self.account_address,
			NFTOwner::NotFound => false,
		}
	}

	async fn verify_receive_data(&self) -> Result<SecretData, SecretError> {
		if self.verify_signature() {
			if self.check_nft_ownership().await {
				Ok(self.parse_secret())
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
			let exist = std::path::Path::new(file_path.as_str()).exists();

			if exist {
				println!(
					"Error storing secrets to TEE : nft_id already exists, nft_id = {}",
					secret.nft_id
				);

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
			}

			let mut f = match std::fs::File::create(file_path) {
				Ok(file) => file,
				Err(err) => {
					println!("Error storing secrets to TEE : error in creating file on disk, nft_id = {}, Error = {}", secret.nft_id, err);

					return (
						StatusCode::OK,
						Json(SecretStoreResponse {
							status: 411,
							nft_id: secret.nft_id,
							cluster_id: 1,
							description: "Error storing secrets to TEE : error in creating file on disk, file creation error"
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
						nft_id: received_secret.parse_secret().nft_id,
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
						nft_id: received_secret.parse_secret().nft_id,
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
						description: "Error retrieving secrets from TEE : nft_id does not exist"
							.to_string(),
						secret_data: "0000_0000".to_owned(),
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
								description:
									"Error retrieving secrets from TEE : nft_id does not exist"
										.to_string(),
								secret_data: SecretData { nft_id: 0, data: Vec::new() }.serialize(),
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
					description: "Success".to_string(),
					secret_data: SecretData { nft_id: data.nft_id, data: nft_secret_share }
						.serialize(),
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
						description: "Error payload is not parsable".to_string(),
						secret_data: SecretData { nft_id: 0, data: Vec::new() }.serialize(),
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
						description: "Error Invalid Signature or NFT owner".to_string(),
						secret_data: SecretData { nft_id: 0, data: Vec::new() }.serialize(),
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
						description: "Error Invalid NFT owner".to_string(),
						secret_data: SecretData { nft_id: 0, data: Vec::new() }.serialize(),
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
	//use bincode::serialize;
	//use hex_literal::hex;
	use sp_keyring::AccountKeyring;
	use subxt::ext::sp_runtime::app_crypto::Ss58Codec;

	#[tokio::test]
	async fn verification_test() {
		let secret_packet = SecretPacket {
			account_address: AccountId32::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6").unwrap(),
			secret_data: "10_CAEAAAAAAAAAAQAhAHMAZQByAGEAaABzACAANQAgAGYAbwAgAGUAcgBhAGgAcwAgAGEAIABzAGkAIABzAGkAaABU".to_string(), 
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
			&sr25519::Public::from_slice(&secret_packet.account_address.as_slice()).unwrap(), //public1
		);
		let vr2 = sr25519::Pair::verify(&signature2, message2, &public2);

		println!("res1 : {}\nres2 : {}", vr1, vr2);

		match secret_packet.verify_receive_data().await {
			Ok(_) => println!("Secret is Valid!"),

			Err(err) => match err {
				SecretError::SignatureInvalid => println!("Signature Error!"),

				SecretError::OwnerInvalid => println!("Invalid Owner!"),

				SecretError::DecodeError => println!("Decode Error"),
			},
		}
	}
}
