#[allow(dead_code)]

use hex::FromHex;
use std::str::FromStr;

#[allow(unused_imports)]
use sp_core::{crypto::Ss58Codec, sr25519, ByteArray, Pair};
use subxt::utils::AccountId32;

use serde::{Deserialize, Serialize};

use axum::Json;
use serde_json::{json, Value};
use tracing::{error};

use crate::chain::chain::{get_current_block_number, get_onchain_data};

/* **********************
  DATA STRUCTURES
********************** */

#[derive(Serialize, Debug)]
pub enum APICALL {
	NFTSTORE,
	NFTRETRIEVE,
	CAPSULESET,
	CAPSULERETRIEVE,
}

#[derive(Serialize, PartialEq)]
pub enum ReturnStatus {
	STORESUCCESS,
	RETRIEVESUCCESS,
	REMOVESUCCESS,

	SIGNERSIGVERIFICATIONFAILED,
	DATASIGVERIFICATIONFAILED,

	OWNERSHIPVERIFICATIONFAILED,

	INVALIDDATAFORMAT,
	INVALIDSIGNERFORMAT,

	INVALIDSIGNERSIGNATURE,
	INVALIDDATASIGNATURE,

	INVALIDOWNERACCOUNT,
	INVALIDSIGNERACCOUNT,
	INVALIDAUTHTOKEN,
	INVALIDNFTID,

	EXPIREDSIGNER,
	EXPIREDREQUEST,

	NFTIDEXISTS,

	DATABASEFAILURE,
	ORACLEFAILURE,

	KEYNOTEXIST,
	KEYNOTACCESSIBLE,
	KEYNOTREADABLE,

	IDISNOTASECRETNFT,
	IDISNOTACAPSULE,
	IDISNOTENCRYPTED,

	NOTBURNT,
	NOTSYNCING,
}

// Errors when parsing signature
#[derive(Debug, PartialEq)]
pub enum SignatureError {
	PREFIXERROR,
	LENGHTERROR,
	TYPEERROR,
}

// Errors
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum VerificationError {
	INVALIDSIGNERSIG(SignatureError),
	INVALIDDATASIG(SignatureError),

	SIGNERVERIFICATIONFAILED,
	DATAVERIFICATIONFAILED,

	OWNERSHIPVERIFICATIONFAILED,

	MALFORMATEDDATA,
	MALFORMATEDSIGNER,
	INVALIDOWNERACCOUNT,
	INVALIDSIGNERACCOUNT,
	INVALIDAUTHTOKEN,

	INVALIDNFTID,

	EXPIREDSIGNER,
	EXPIREDDATA,

	IDISNOTENCRYPTED,
}

// Validity time of Keyshare Data
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
}

// Keyshare Data structure
#[derive(Clone, Debug, PartialEq)]
pub struct StoreKeyshareData {
	pub nft_id: u32,
	pub data: Vec<u8>,
	pub auth_token: AuthenticationToken,
}

// Packet-signer and validity of it
#[derive(Clone, PartialEq, Debug)]
pub struct Signer {
	account: sr25519::Public,
	auth_token: AuthenticationToken,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreKeysharePacket {
	pub owner_address: sr25519::Public,

	// Signed by owner
	signer_address: String,
	signersig: String,

	// Signed by signer
	pub secret_data: String, // TODO: Replace by "SecretData" JWT/JWS
	pub signature: String,
}

// Keyshare Data structure
#[derive(Clone, Debug, PartialEq)]
pub struct RetrieveKeyshareData {
	pub nft_id: u32,
	pub auth_token: AuthenticationToken,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RetrieveKeysharePacket {
	pub owner_address: sr25519::Public,
	pub data: String, // TODO: Replace by "SecretData" JWT/JWS
	pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RemoveKeysharePacket {
	pub owner_address: sr25519::Public,
	pub nft_id: u32,
}

#[derive(Debug, PartialEq)]
pub enum KeyshareOwner {
	Owner(AccountId32),
	NotFound,
}

impl VerificationError {
	pub fn express_verification_error(
		self,
		call: APICALL,
		caller: String,
		nft_id: u32,
		enclave_id: String,
	) -> Json<Value> {
		match self {
			// SIGNER SIGNATURE FORMAT
			VerificationError::INVALIDSIGNERSIG(e) => {
				let status = serde_json::to_string(&ReturnStatus::INVALIDSIGNERSIGNATURE).unwrap();
				let description =
					format!("TEE Key-share {:?}: Invalid request signature format, {:?} ", call, e);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// DATA SIGNATURE FORMAT
			VerificationError::INVALIDDATASIG(e) => {
				let status = serde_json::to_string(&ReturnStatus::INVALIDDATASIGNATURE).unwrap();
				let description =
					format!("TEE Key-share {:?}: Invalid request data signature format, {:?}", call, e);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// OWNER ACCOUNT FORMAT
			VerificationError::INVALIDOWNERACCOUNT => {
				let status = serde_json::to_string(&ReturnStatus::INVALIDOWNERACCOUNT).unwrap();
				let description = format!("TEE Key-share {:?}: Invalid owner address format", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// SIGNER ACCOUNT FORMAT
			VerificationError::INVALIDSIGNERACCOUNT => {
				let status = serde_json::to_string(&ReturnStatus::INVALIDSIGNERACCOUNT).unwrap();
				let description =
					format!("TEE Key-share {:?}: Invalid signer address format", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// VERIFY SIGNER TO BE SIGNED BY THE OWNER
			VerificationError::SIGNERVERIFICATIONFAILED => {
				let status =
					serde_json::to_string(&ReturnStatus::SIGNERSIGVERIFICATIONFAILED).unwrap();
				let description = format!("TEE Key-share {:?}: Signer signature verification failed, Signer is not approved by NFT owner", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// VERIFY SIGNER TO BE SIGNED BY THE OWNER
			VerificationError::DATAVERIFICATIONFAILED => {
				let status =
					serde_json::to_string(&ReturnStatus::DATASIGVERIFICATIONFAILED).unwrap();
				let description = format!("TEE Key-share {:?}: Data signature verification failed.", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// AUTHENTICATION-TOKEN FORMAT
			VerificationError::INVALIDAUTHTOKEN => {
				let status = serde_json::to_string(&ReturnStatus::INVALIDAUTHTOKEN).unwrap();
				let description =
					format!("TEE Key-share {:?}: Invalid authentication-token format ", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// NFTID FORMAT
			VerificationError::INVALIDNFTID => {
				let status = serde_json::to_string(&ReturnStatus::INVALIDNFTID).unwrap();
				let description =
					format!("TEE Key-share {:?}: The nft-id is not a valid number", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// VERIFY ONCHAIN NFTID TO BE OWNED BY SPECIFIED OWNER
			VerificationError::OWNERSHIPVERIFICATIONFAILED => {
				let status =
					serde_json::to_string(&ReturnStatus::OWNERSHIPVERIFICATIONFAILED).unwrap();
				let description =
					format!("TEE Key-share {:?}: The nft-id is not owned by this owner", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// EPIRATION PERIOD OF SIGNER ACCOUNT  (AUTHENTICATION-TOKEN)
			VerificationError::EXPIREDSIGNER => {
				let status = serde_json::to_string(&ReturnStatus::EXPIREDSIGNER).unwrap();
				let description = format!("TEE Key-share {:?}: The signer account has been expired or is not in valid range.", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// EPIRATION PERIOD OF REQUEST DATA  (AUTHENTICATION-TOKEN)
			VerificationError::EXPIREDDATA => {
				let status = serde_json::to_string(&ReturnStatus::EXPIREDREQUEST).unwrap();
				let description = format!("TEE Key-share {:?}: The request data field has been expired  or is not in valid range.", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// IS NOT ENCRYPTED ENTITY
			VerificationError::IDISNOTENCRYPTED => {
				let status = serde_json::to_string(&ReturnStatus::IDISNOTENCRYPTED).unwrap();
				let description = format!("TEE Key-share {:?}: The nft-id is a normal NFT, only secret-nft and capsule need TEE.", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// PARSE DATA PACKET FAILED
			VerificationError::MALFORMATEDDATA => {
				let status = serde_json::to_string(&ReturnStatus::INVALIDDATAFORMAT).unwrap();
				let description = format!("TEE Key-share {:?}: Failed to parse Data field", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},

			// PARSE SIGNER PACKET FAILED
			VerificationError::MALFORMATEDSIGNER => {
				let status = serde_json::to_string(&ReturnStatus::INVALIDSIGNERFORMAT).unwrap();
				let description =
					format!("TEE Key-share {:?}: Failed to parse Signer field.", call);
				error!("{}, requester : {}", description, caller);

				Json(json! ({
					"status": status,
					"nft_id": nft_id,
					"enclave_id": enclave_id,
					"description": description,
				}))
			},
		}
	}
}

// Fetch onchain owenrship of nft/capsule id
pub async fn get_onchain_owner(nft_id: u32) -> KeyshareOwner {
	let data = get_onchain_data(nft_id).await;

	let owner = match data {
		Some(capsule_data) => KeyshareOwner::Owner(capsule_data.owner),
		None => KeyshareOwner::NotFound,
	};

	owner
}

pub struct OnchainStatus {
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
pub async fn get_onchain_status(nft_id: u32) -> OnchainStatus {
	let capsule_data = get_onchain_data(nft_id).await;

	let capsule_state = match capsule_data {
		Some(state) => state,
		None =>
			return OnchainStatus {
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
			},
	};

	OnchainStatus {
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
AUTHENTICATION TOKEN IMPLEMENTATION
----------------------------------*/

// Retrieving the stored Keyshare
impl AuthenticationToken {
	// TODO: use json canonicalization of JOSE/JWT encoder
	pub fn serialize(self) -> String {
		self.block_number.to_string() + "_" + &self.block_validation.to_string()
	}

	pub async fn is_valid(self) -> bool {
		let last_block_number = get_current_block_number().await;
		(last_block_number > self.block_number - 3) // for finalization delay
			&& (last_block_number < self.block_number + self.block_validation + 3)
	}
}

/* ----------------------------------
   SECRET-DATA IMPLEMENTATION
----------------------------------*/

// Retrieving the stored Keyshare
impl StoreKeyshareData {
	// TODO: use json canonicalization of JOSE/JWT encoder
	pub fn serialize(self) -> String {
		self.nft_id.to_string() +
			"_" + &String::from_utf8(self.data).unwrap() +
			"_" + &self.auth_token.serialize()
	}
}

/* ----------------------------------
SECRET-PACKET IMPLEMENTATION
----------------------------------*/

impl StoreKeysharePacket {
	// Signer string to public key
	pub fn get_signer(&self) -> Result<Signer, VerificationError> {
		let mut signer = self.signer_address.clone();

		if signer.starts_with("<Bytes>") && signer.ends_with("</Bytes>") {
			signer = signer
				.strip_prefix("<Bytes>")
				.unwrap()
				.strip_suffix("</Bytes>")
				.unwrap()
				.to_string();
		}

		let parsed_data: Vec<&str> = if signer.contains("_") {
			signer.split("_").collect()
		} else {
			return Err(VerificationError::MALFORMATEDSIGNER)
		};

		if parsed_data.len() < 3 {
			return Err(VerificationError::MALFORMATEDSIGNER)
		}

		let account = match sr25519::Public::from_ss58check(parsed_data[0]) {
			Ok(acc) => acc,
			Err(_) => return Err(VerificationError::INVALIDSIGNERACCOUNT),
		};

		let block_num = match parsed_data[1].parse::<u32>() {
			Ok(bn) => bn,
			Err(_) => return Err(VerificationError::INVALIDAUTHTOKEN),
		};

		let block_valid = match parsed_data[2].parse::<u32>() {
			Ok(bv) => bv,
			Err(_) => return Err(VerificationError::INVALIDAUTHTOKEN),
		};

		Ok(Signer {
			account,
			auth_token: AuthenticationToken {
				block_number: block_num,
				block_validation: block_valid,
			},
		})
	}

	// TODO: use json canonicalization of JOSE/JWT decoder
	pub fn parse_store_data(&self) -> Result<StoreKeyshareData, VerificationError> {
		let mut data = self.secret_data.clone();

		if data.starts_with("<Bytes>") && data.ends_with("</Bytes>") {
			data = data
				.strip_prefix("<Bytes>")
				.unwrap()
				.strip_suffix("</Bytes>")
				.unwrap()
				.to_string();
		}

		let parsed_data: Vec<&str> = if data.contains("_") {
			data.split("_").collect()
		} else {
			return Err(VerificationError::MALFORMATEDDATA)
		};

		if parsed_data.len() < 4 {
			return Err(VerificationError::MALFORMATEDDATA)
		}

		let nft_id = match parsed_data[0].parse::<u32>() {
			Ok(n) => n,
			Err(_) => return Err(VerificationError::INVALIDNFTID),
		};

		let block_number = match parsed_data[2].parse::<u32>() {
			Ok(bn) => bn,
			Err(_) => return Err(VerificationError::INVALIDAUTHTOKEN),
		};

		let block_validation = match parsed_data[3].parse::<u32>() {
			Ok(bv) => bv,
			Err(_) => return Err(VerificationError::INVALIDAUTHTOKEN),
		};

		Ok(StoreKeyshareData {
			nft_id,

			data: if !parsed_data[1].is_empty() {
				parsed_data[1].as_bytes().to_vec()
			} else {
				Vec::new()
			},

			auth_token: AuthenticationToken { block_number, block_validation },
		})
	}

	// Extract signatures from hex
	pub fn parse_signature(&self, account: &str) -> Result<sr25519::Signature, SignatureError> {
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
	pub async fn verify_signer(&self) -> Result<bool, VerificationError> {
		let signer = match self.get_signer() {
			Ok(pk) => pk,
			Err(_) => return Err(VerificationError::INVALIDSIGNERACCOUNT),
		};

		if !signer.auth_token.is_valid().await {
			return Err(VerificationError::EXPIREDSIGNER)
		}

		let signersig = match self.parse_signature("signer") {
			Ok(sig) => sig,
			Err(e) => return Err(VerificationError::INVALIDSIGNERSIG(e)),
		};

		let result =
			sr25519::Pair::verify(&signersig, self.signer_address.clone(), &self.owner_address);
		Ok(result)
	}

	// Verify Keyshare data
	pub async fn verify_data(&self) -> Result<bool, VerificationError> {
		let signer = self.get_signer().unwrap();

		let packetsig = match self.parse_signature("owner") {
			Ok(sig) => sig,
			Err(e) => return Err(VerificationError::INVALIDDATASIG(e)),
		};

		let data = match self.parse_store_data() {
			Ok(sec) => sec,
			Err(e) => return Err(e),
		};

		let nft_status = get_onchain_status(data.nft_id).await;

		if !nft_status.is_secret && !nft_status.is_capsule {
			return Err(VerificationError::IDISNOTENCRYPTED)
		}

		if !data.auth_token.is_valid().await {
			return Err(VerificationError::EXPIREDDATA)
		}

		let result = sr25519::Pair::verify(&packetsig, self.secret_data.clone(), &signer.account);

		Ok(result)
	}

	// Check nft/capsule owner
	pub async fn check_ownership(&self, nft_id: u32) -> bool {
		let capsule_owner = get_onchain_owner(nft_id).await;
		match capsule_owner {
			KeyshareOwner::Owner(owner) =>
				owner ==
					subxt::utils::AccountId32::from_str(&self.owner_address.to_string()).unwrap(),
			KeyshareOwner::NotFound => false,
		}
	}

	pub async fn verify_store_request(&self) -> Result<StoreKeyshareData, VerificationError> {
		match self.verify_signer().await {
			Ok(true) => {
				let data = match self.parse_store_data() {
					Ok(sec) => sec,
					Err(e) => return Err(e),
				};

				if self.check_ownership(data.nft_id).await {
					match self.verify_data().await {
						Ok(true) => Ok(data),
						Ok(false) => Err(VerificationError::DATAVERIFICATIONFAILED),
						Err(e) => Err(e),
					}
				} else {
					Err(VerificationError::OWNERSHIPVERIFICATIONFAILED)
				}
			},

			Ok(false) => Err(VerificationError::SIGNERVERIFICATIONFAILED),

			Err(e) => Err(e),
		}
	}

	#[allow(dead_code)]
	pub async fn verify_free_store_request(&self) -> Result<StoreKeyshareData, VerificationError> {
		match self.verify_signer().await {
			Ok(true) => {
				let data = match self.parse_store_data() {
					Ok(sec) => sec,
					Err(e) => return Err(e),
				};

				match self.verify_data().await {
					Ok(true) => Ok(data),
					Ok(false) => Err(VerificationError::DATAVERIFICATIONFAILED),
					Err(e) => Err(e),
				}
			},

			Ok(false) => Err(VerificationError::SIGNERVERIFICATIONFAILED),

			Err(e) => Err(e),
		}
	}
}

impl RetrieveKeysharePacket {
	// Extract signatures from hex
	pub fn parse_signature(&self) -> Result<sr25519::Signature, SignatureError> {
		let sig = self.signature.clone();

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

	// TODO: use json canonicalization of JOSE/JWT decoder
	pub fn parse_retrieve_data(&self) -> Result<RetrieveKeyshareData, VerificationError> {
		let mut data = self.data.clone();

		if data.starts_with("<Bytes>") && data.ends_with("</Bytes>") {
			data = data
				.strip_prefix("<Bytes>")
				.unwrap()
				.strip_suffix("</Bytes>")
				.unwrap()
				.to_string();
		}

		let parsed_data: Vec<&str> = if data.contains("_") {
			data.split("_").collect()
		} else {
			return Err(VerificationError::MALFORMATEDDATA)
		};

		if parsed_data.len() < 3 {
			return Err(VerificationError::MALFORMATEDDATA)
		}

		let nft_id = match parsed_data[0].parse::<u32>() {
			Ok(n) => n,
			Err(_) => return Err(VerificationError::INVALIDNFTID),
		};

		let block_number = match parsed_data[1].parse::<u32>() {
			Ok(bn) => bn,
			Err(_) => return Err(VerificationError::INVALIDAUTHTOKEN),
		};

		let block_validation = match parsed_data[2].parse::<u32>() {
			Ok(bv) => bv,
			Err(_) => return Err(VerificationError::INVALIDAUTHTOKEN),
		};

		Ok(RetrieveKeyshareData {
			nft_id,
			auth_token: AuthenticationToken { block_number, block_validation },
		})
	}

	// Verify Keyshare data
	pub async fn verify_data(&self) -> Result<bool, VerificationError> {
		let data = match self.parse_retrieve_data() {
			Ok(sec) => sec,
			Err(e) => return Err(e),
		};

		let nft_status = get_onchain_status(data.nft_id).await;

		if !nft_status.is_secret && !nft_status.is_capsule {
			return Err(VerificationError::IDISNOTENCRYPTED)
		}

		if !data.auth_token.is_valid().await {
			return Err(VerificationError::EXPIREDDATA)
		}

		let sig = match self.parse_signature() {
			Ok(sig) => sig,
			Err(e) => return Err(VerificationError::INVALIDSIGNERSIG(e)),
		};

		let result = sr25519::Pair::verify(&sig, self.data.clone(), &self.owner_address);

		Ok(result)
	}

	// Check nft/capsule owner
	pub async fn check_ownership(&self, nft_id: u32) -> bool {
		let capsule_owner = get_onchain_owner(nft_id).await;
		match capsule_owner {
			KeyshareOwner::Owner(owner) =>
				owner ==
					subxt::utils::AccountId32::from_str(&self.owner_address.to_string()).unwrap(),
			KeyshareOwner::NotFound => false,
		}
	}

	pub async fn verify_retrieve_request(&self) -> Result<RetrieveKeyshareData, VerificationError> {
		let data = match self.parse_retrieve_data() {
			Ok(sec) => sec,
			Err(e) => return Err(e),
		};

		if self.check_ownership(data.nft_id).await {
			match self.verify_data().await {
				Ok(true) => Ok(data),
				Ok(false) => Err(VerificationError::DATAVERIFICATIONFAILED),
				Err(e) => Err(e),
			}
		} else {
			Err(VerificationError::OWNERSHIPVERIFICATIONFAILED)
		}
	}


	#[allow(dead_code)]
	pub async fn verify_free_retrieve_request(
		&self,
	) -> Result<RetrieveKeyshareData, VerificationError> {
		let data = match self.parse_retrieve_data() {
			Ok(sec) => sec,
			Err(e) => return Err(e),
		};

		match self.verify_data().await {
			Ok(true) => Ok(data),
			Ok(false) => Err(VerificationError::DATAVERIFICATIONFAILED),
			Err(e) => Err(e),
		}
	}
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {

	use super::*;

	/* ----------------------
		 PARSING
	---------------------- */
	#[tokio::test]
	async fn parse_data_from_sdk_test() {
		let packet_sdk = StoreKeysharePacket {
			owner_address: sr25519::Public::from_slice(&[0u8; 32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			secret_data: "163_1234567890abcdef_1000_10000".to_string(),
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};

		// Signed in SDK
		let data = packet_sdk.parse_store_data().unwrap();

		assert_eq!(data.nft_id, 163);
		assert_eq!(data.data, b"1234567890abcdef");
		assert_eq!(data.auth_token.block_number, 1000);
		assert_eq!(data.auth_token.block_validation, 10000);
	}

	#[tokio::test]
	async fn parse_data_from_polkadotjs_test() {
		let packet_polkadotjs = StoreKeysharePacket {
			owner_address: sr25519::Public::from_slice(&[0u8; 32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			secret_data: "<Bytes>163_1234567890abcdef_1000_10000</Bytes>".to_string(),
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};
		// Signed in Polkadot.JS
		let data = packet_polkadotjs.parse_store_data().unwrap();

		assert_eq!(data.nft_id, 163);
		assert_eq!(data.data, b"1234567890abcdef");
		assert_eq!(data.auth_token.block_number, 1000);
		assert_eq!(data.auth_token.block_validation, 10000);
	}

	#[tokio::test]
	async fn get_public_key_test() {
		let packet_sdk = StoreKeysharePacket {
			owner_address: sr25519::Public::from_ss58check(
				"5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6",
			)
			.unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			secret_data: "xxx".to_string(),
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};

		let pk = packet_sdk.owner_address;

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

		let mut packet_sdk  = StoreKeysharePacket {
			owner_address: sr25519::Public::from_slice(&[0u8;32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8;32]).unwrap().to_string(),
			secret_data: "xxx".to_string(), 
			signature: "0x42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string(),
			signersig: "xxx".to_string(),
		};

		let sig = packet_sdk.parse_signature("owner").unwrap();
		assert_eq!(sig, correct_sig);

		// missing 0x prefix
		packet_sdk.signature = "42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		let sig = packet_sdk.parse_signature("owner").unwrap_err();
		assert_eq!(sig, SignatureError::PREFIXERROR);

		// Incorrect Length
		packet_sdk.signature = "0x2bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		let sig = packet_sdk.parse_signature("owner").unwrap_err();
		assert_eq!(sig, SignatureError::LENGHTERROR);
	}

	/* ----------------------
		 VERIFICATION
	---------------------- */

	#[tokio::test]
	async fn verify_data_test() {
		let mut packet = StoreKeysharePacket {
			owner_address:sr25519::Public::from_ss58check("5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET").unwrap(),
			signer_address:"5GxffGgHzTFu8mmHCRbw9YZkkcwTZreL2FVLQHVb4FVgEPcE_214188_1000000".to_string(),
			signersig:"0xa4f331ec6c6197a95122f171fbbb561f528085b2ca5176d676596eea03669718a7047cd29db3da4f5c48d3eb9df5648c8b90851fe9781dfaa11aef0eb1e6b88a".to_string(),
			secret_data:"324_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_214188_1000000".to_string(),
			signature:"0x64bc35276740fe6b196c7f18b22be553088555a1a282269d8b85546fcd7e68635392b0fc16e535a6e9187d5e6cbc02fd2c3b62546e848754942023176152f488".to_string(),
		};

		// correct
		assert_eq!(packet.verify_data().await.unwrap(), true);

		// changed data error
		packet.secret_data =
			"324_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-O)_214188_1000000".to_string();
		assert_eq!(packet.verify_data().await.unwrap(), false);

		// changed signer error
		packet.signer_address =
			"5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET_214188_1000000".to_string();
		packet.secret_data =
			"324_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_214188_10000000"
				.to_string();
		assert_eq!(packet.verify_data().await.unwrap(), false);

		// changed signature error
		packet.owner_address =
			sr25519::Public::from_ss58check("5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy")
				.unwrap();
		packet.signature = "0xa64400b64bed9b77a59e5a5f1d2e82489fcf20fcc5ff563d755432ffd2ef5c57021478051f9f93e8448fa4cb4c4900d406c263588898963d3d7960a3a5c16485".to_string();
		assert_eq!(packet.verify_data().await.unwrap(), false);

		// expired data error
		packet.secret_data =
			"324_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_214188_10".to_string();
		packet.signature = "0x2879d6c3f63c108875219c67ce443c823c0a51b590da0aba4441c239f307354a8cbb983d9200bf67079b38c348b114d6a98d3b35cc8b4a20b4711e0e0a3e0582".to_string();
		assert_eq!(packet.verify_data().await.unwrap_err(), VerificationError::EXPIREDDATA);
	}

	#[tokio::test]
	async fn verify_polkadotjs_request_test() {
		let owner = sr25519::Pair::generate().0;
		let signer = sr25519::Pair::generate().0;
		let signer_address =
			"<Bytes>".to_string() + &signer.public().to_ss58check() + "_214299_1000000</Bytes>";
		let signersig = owner.sign(signer_address.as_bytes());
		let data = "<Bytes>324_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_214299_1000000</Bytes>";
		let signature = signer.sign(data.as_bytes());

		let packet = StoreKeysharePacket {
			owner_address: owner.public(),
			signer_address: signer_address.to_string(),
			signersig: format!("{}{:?}", "0x", signersig),
			secret_data: data.to_string(),
			signature: format!("{}{:?}", "0x", signature),
		};

		let correct_data = StoreKeyshareData {
			nft_id: 324,
			data: "thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)".as_bytes().to_vec(),
			auth_token: AuthenticationToken { block_number: 214299, block_validation: 1000000 },
		};

		// correct
		assert_eq!(packet.verify_free_store_request().await.unwrap(), correct_data);
	}

	#[tokio::test]
	async fn verify_signer_request_test() {
		// Test
		let owner = sr25519::Pair::generate().0;
		let signer = sr25519::Pair::generate().0;

		let signer_address = signer.public().to_ss58check() + "_214299_1000000";
		let signersig = owner.sign(signer_address.as_bytes());
		let data = "494_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_214299_1000000";
		let signature = signer.sign(data.as_bytes());

		let mut packet = StoreKeysharePacket {
			owner_address: owner.public(),
			signer_address: signer_address.to_string(),
			signersig: format!("{}{:?}", "0x", signersig),
			secret_data: data.to_string(),
			signature: format!("{}{:?}", "0x", signature),
		};

		let correct_data = StoreKeyshareData {
			nft_id: 494,
			data: "thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)".as_bytes().to_vec(),
			auth_token: AuthenticationToken { block_number: 214299, block_validation: 1000000 },
		};

		// correct
		assert_eq!(packet.verify_free_store_request().await.unwrap(), correct_data);

		// changed owner error
		packet.owner_address =
			sr25519::Public::from_ss58check("5DLgQdhNz8B7RTKKMRCDwJWWbqu5FRYsLgJivLhVaYEsCpin")
				.unwrap();
		assert_eq!(
			packet.verify_free_store_request().await.unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// changed signer error
		packet.owner_address = owner.public();
		packet.signer_address =
			sr25519::Pair::generate().0.public().to_ss58check() + "_214299_1000000";
		assert_eq!(
			packet.verify_free_store_request().await.unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// changed signer signature error
		packet.signer_address = signer.public().to_ss58check() + "_214299_1000000";
		packet.signersig = "0xa4f331ec6c6197a95122f171fbbb561f528085b2ca5176d676596eea03669718a7047cd29db3da4f5c48d3eb9df5648c8b90851fe9781dfaa11aef0eb1e6b88a".to_string();
		assert_eq!(
			packet.verify_free_store_request().await.unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// expired signer error
		let expired_signer_address = signer.public().to_ss58check() + "_214299_10";
		let expired_signersig = owner.sign(signer_address.as_bytes());

		packet.signer_address = expired_signer_address;
		packet.signersig = format!("{}{:?}", "0x", expired_signersig);

		assert_eq!(
			packet.verify_free_store_request().await.unwrap_err(),
			VerificationError::EXPIREDSIGNER
		);
	}

	#[tokio::test]
	async fn generate_request_test() {
		let owner = sr25519::Pair::from_phrase(
			"hockey fine lawn number explain bench twenty blue range cover egg sibling",
			None,
		)
		.unwrap()
		.0;
		let signer = sr25519::Pair::from_phrase(
			"steel announce garden guilt direct give morning gadget milk census poem faith",
			None,
		)
		.unwrap()
		.0;

		let signer_address = signer.public().to_ss58check() + "_214299_1000000";
		let signersig = owner.sign(signer_address.as_bytes());
		let data = "494_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_214299_1000000";
		let signature = signer.sign(data.as_bytes());

		let packet = StoreKeysharePacket {
			owner_address: owner.public(),
			signer_address: signer_address.to_string(),
			signersig: format!("{}{:?}", "0x", signersig),
			secret_data: data.to_string(),
			signature: format!("{}{:?}", "0x", signature),
		};

		println!("StoreKeysharePacket = {}\n", serde_json::to_string_pretty(&packet).unwrap());

		let data = "494_214299_1000000";
		let signature = owner.sign(data.as_bytes());
		let packet = RetrieveKeysharePacket {
			owner_address: owner.public(),
			data: data.to_string(),
			signature: format!("{}{:?}", "0x", signature),
		};

		println!("RetrieveKeysharePacket = {}\n", serde_json::to_string_pretty(&packet).unwrap());


		let packet = RemoveKeysharePacket {
			owner_address: signer.public(), // Because anybody can ask to remove burnt data
			nft_id:494,
		};

		println!("RemoveKeysharePacket = {}\n", serde_json::to_string_pretty(&packet).unwrap());

	}
}
