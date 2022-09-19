use crate::chain::chain::get_nft_data;
use async_trait::async_trait;
use axum::{extract, response::IntoResponse};
use std::{
	fs::create_dir_all,
	io::{Read, Write},
};

use subxt::ext::{
	sp_core::{sr25519, ByteArray, Pair},
	sp_runtime::AccountId32,
};
//use crate::chain::chain::ternoa::runtime_types::sp_core::crypto::AccountId32;

//use subxt::ext::sp_core::crypto::Ss58C&&odec;
use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

const NFT_DIR_PATH: &str = "./credentials/nft/";

#[derive(Debug)]
pub enum SecretError {
	DecodeError,
	SignatureInvalid,
	OwnerInvalid,
}

#[derive(Deserialize, Clone)]
pub struct SecretPost {
	account_address: AccountId32,
	secret_data: Vec<u8>,
	signature: sr25519::Signature,
}

#[derive(Serialize)]
pub struct SecretPostResponse {
	status: u32,
	cluster_id: u32,
	description: String,
}

#[derive(Deserialize, Serialize)]
pub struct SecretData {
	nft_id: u32,
	data: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SecretGet {
	account_address: AccountId32,
	data: Vec<u8>,
	signature: sr25519::Signature,
}

#[derive(Serialize)]
pub struct SecretGetResponse {
	status: u32,
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
	fn from_bytes(body: Vec<u8>) -> Self;
	fn get_public_key(&self) -> sr25519::Public;
	fn verify_signature(&self) -> bool;
	async fn check_nft_ownership(&self) -> bool;
	async fn verify_receive_data(&self) -> Result<SecretData, SecretError>;
}

#[async_trait]
impl VerifyNFT for SecretPost {
	fn from_bytes(body: Vec<u8>) -> SecretPost {
		let decoded_secret_data: SecretPost = deserialize(&body).unwrap();
		decoded_secret_data
	}

	fn get_public_key(&self) -> sr25519::Public {
		sr25519::Public::from_slice(self.account_address.clone().as_slice()).expect("Valid address")
	}

	fn verify_signature(&self) -> bool {
		let account_pubkey = self.get_public_key();
		sr25519::Pair::verify(&self.signature.clone(), self.secret_data.clone(), &account_pubkey)
	}

	async fn check_nft_ownership(&self) -> bool {
		let decoded_secret_data: SecretData = deserialize(&self.secret_data.clone()).unwrap();
		let nft_id = decoded_secret_data.nft_id;
		let nft_owner = get_nft_owner(nft_id).await;
		match nft_owner {
			NFTOwner::Owner(owner) => owner == self.account_address,
			NFTOwner::NotFound => false,
		}
	}

	async fn verify_receive_data(&self) -> Result<SecretData, SecretError> {
		if self.verify_signature() {
			if self.check_nft_ownership().await {
				let decoded_secret_data: SecretData = deserialize(&self.secret_data).unwrap();
				Ok(decoded_secret_data)
			} else {
				Err(SecretError::OwnerInvalid)
			}
		} else {
			Err(SecretError::SignatureInvalid)
		}
	}
}

#[async_trait]
impl VerifyNFT for SecretGet {
	fn from_bytes(body: Vec<u8>) -> Self {
		let req: SecretGet = deserialize(&body).unwrap();
		req
	}

	fn get_public_key(&self) -> sr25519::Public {
		sr25519::Public::from_slice(self.account_address.clone().as_slice()).expect("Valid address")
	}

	fn verify_signature(&self) -> bool {
		let account_pubkey = self.get_public_key();
		sr25519::Pair::verify(&self.signature.clone(), &self.data, &account_pubkey)
	}

	async fn check_nft_ownership(&self) -> bool {
		let secret_data: SecretData = deserialize(&self.data).unwrap();
		let nft_owner = get_nft_owner(secret_data.nft_id).await;
		match nft_owner {
			NFTOwner::Owner(owner) => owner == self.account_address,
			NFTOwner::NotFound => false,
		}
	}

	async fn verify_receive_data(&self) -> Result<SecretData, SecretError> {
		if self.verify_signature() {
			if self.check_nft_ownership().await {
				let secret_data: SecretData = deserialize(&self.data).unwrap();
				Ok(secret_data)
			} else {
				Err(SecretError::OwnerInvalid)
			}
		} else {
			Err(SecretError::SignatureInvalid)
		}
	}
}

/* POST SECRET */
pub async fn store_secret_shares(
	extract::Json(received_secret): extract::Json<SecretPost>,
) -> impl IntoResponse {
	let verified_secret = received_secret.verify_receive_data().await;

	match verified_secret {
		Ok(secret) => {
			create_dir_all(NFT_DIR_PATH).unwrap();
			let file_path = NFT_DIR_PATH.to_owned() + &secret.nft_id.to_string() + ".secret";
			let mut f = std::fs::File::create(file_path).expect("create secret nft file, failed");
			f.write_all(&secret.data).unwrap();

			println!(
				"Secret is successfully stored to TEE, nft_id = {} by Owner = {}",
				secret.nft_id, received_secret.account_address
			);

			return axum::Json(SecretPostResponse {
				status: 200,
				cluster_id: 1,
				description: "Secret is successfully stored to TEE".to_string(),
			})
		},

		Err(err) => match err {
			SecretError::SignatureInvalid => {
				println!("Error storing secrets to TEE : Invalid Request Signature");

				return axum::Json(SecretPostResponse {
					status: 400,
					cluster_id: 1,
					description: "Error storing secrets to TEE : Invalid Request Signature"
						.to_string(),
				})
			},

			SecretError::OwnerInvalid => {
				println!("Error storing secrets to TEE : Invalid NFT Owner");

				return axum::Json(SecretPostResponse {
					status: 401,
					cluster_id: 1,
					description: "Error storing secrets to TEE : Invalid NFT Owner".to_string(),
				})
			},

			SecretError::DecodeError => todo!(),
		},
	}
}

/* GET SECRET */
pub async fn retrieve_secret_shares(
	extract::Json(requested_secret): extract::Json<SecretGet>,
) -> impl IntoResponse {
	let verified_req = requested_secret.verify_receive_data().await;
	match verified_req {
		Ok(data) => {
			let file_path = NFT_DIR_PATH.to_owned() + &data.nft_id.to_string() + ".secret";
			let mut file = std::fs::File::open(file_path).unwrap();
			let mut nft_secret_share = Vec::<u8>::new();

			file.read_to_end(&mut nft_secret_share).unwrap();

			println!(
				"Secret shares of {} retrieved by {}",
				data.nft_id, requested_secret.account_address
			);

			axum::Json(SecretGetResponse {
				status: 200,
				cluster_id: 1,
				secret_data: SecretData { nft_id: data.nft_id, data: nft_secret_share },
			})
		},
		Err(err) => match err {
			SecretError::DecodeError => todo!(),

			SecretError::SignatureInvalid => axum::Json(SecretGetResponse {
				status: 400,
				cluster_id: 1,
				secret_data: SecretData {
					nft_id: 0,
					data: "Error Invalid Signature or NFT owner".as_bytes().to_vec(),
				},
			}),

			SecretError::OwnerInvalid => axum::Json(SecretGetResponse {
				status: 400,
				cluster_id: 1,
				secret_data: SecretData {
					nft_id: 0,
					data: "Error Invalid Signature or NFT owner".as_bytes().to_vec(),
				},
			}),
		},
	}
}

/* TEST */
#[cfg(test)]
mod test {
	use super::*;
	use hex_literal::hex;
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

		let sd = SecretData {
			nft_id: 48384,
			data: "This is one share of eight shares of secret!".into(),
		};

		let ser_sd: Vec<u8> = serialize(&sd).unwrap();
		//println!("serialized secure data = {}", ser_sd);

		let sp = SecretPost {
			//account_address: AccountId32::from(public),
			account_address: AccountId32::from_ss58check(
				"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET",
			)
			.unwrap(),
			secret_data: ser_sd.clone(),
			signature: kp.sign(&ser_sd),
		};

		//println!("signature = {:-?}", kp.sign(&ser_sd));

		match sp.verify_receive_data().await {
			Ok(secret) => println!("Secret is Valid!"),

			Err(err) => match err {
				SecretError::SignatureInvalid => println!("Signature Error!"),

				SecretError::OwnerInvalid => println!("Invalid Owner!"),

				SecretError::DecodeError => println!("Decode Error"),
			},
		}
	}
}
