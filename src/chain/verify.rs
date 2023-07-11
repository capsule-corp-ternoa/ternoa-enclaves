#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::upper_case_acronyms)]

use hex::FromHex;
use std::str::FromStr;

use sp_core::{crypto::Ss58Codec, sr25519, ByteArray, Pair};
use subxt::utils::AccountId32;

use serde::{Deserialize, Serialize};

use axum::{
	http::{header, StatusCode},
	response::IntoResponse,
	Json,
};

use serde_json::{json, Value};
use tracing::{debug, error, info};

use crate::{
	chain::core::{
		get_current_block_number, get_onchain_delegatee, get_onchain_nft_data,
		get_onchain_rent_contract,
	},
	servers::http_server::SharedState,
};

use super::core::get_current_block_number_new_api;

const MAX_VALIDATION_PERIOD: u32 = 20;
const MAX_BLOCK_VARIATION: u32 = 5;

/* **********************
  DATA STRUCTURES
********************** */

/// API Call
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
	REQUESTERVERIFICATIONFAILED,

	INVALIDDATAFORMAT,
	INVALIDSIGNERFORMAT,

	INVALIDSIGNERSIGNATURE,
	INVALIDDATASIGNATURE,

	INVALIDOWNERADDRESS,
	INVALIDSIGNERADDRESS,
	INVALIDAUTHTOKEN,
	INVALIDKEYSHARE,
	INVALIDNFTID,

	KEYSHAREISTOOSHORT,
	KEYSHAREISTOOLONG,

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
	NOTSYNCED,

	INTERNALSTATELOCKED,
	InvalidBlockNumber,
}

// Errors when parsing signature
#[derive(Serialize, Debug, PartialEq)]
pub enum SignatureError {
	PREFIXERROR,
	LENGHTERROR,
	TYPEERROR,
}

// Errors
#[allow(dead_code)]
#[derive(Serialize, Debug, PartialEq)]
pub enum VerificationError {
	INVALIDSIGNERSIG(SignatureError),
	INVALIDDATASIG(SignatureError),

	SIGNERVERIFICATIONFAILED,
	DATAVERIFICATIONFAILED,

	OWNERSHIPVERIFICATIONFAILED,
	REQUESTERVERIFICATIONFAILED,

	MALFORMATEDDATA,
	MALFORMATEDSIGNER,
	INVALIDOWNERADDRESS,
	INVALIDSIGNERADDRESS,

	KEYSHAREISTOOSHORT,
	KEYSHAREISTOOLONG,

	INVALIDAUTHTOKEN,
	INVALIDKEYSHARE,
	INVALIDNFTID,

	EXPIREDSIGNER(ValidationResult),
	EXPIREDDATA(ValidationResult),

	IDISNOTSECRETNFT,
	IDISNOTCAPSULE,
	NOTSYNCING,
	NOTSYNCED,
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
	pub keyshare: Vec<u8>,
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
	pub data: String, // TODO: Replace by "SecretData" JWT/JWS
	pub signature: String,
}

// Keyshare Data structure
#[derive(Clone, Debug, PartialEq)]
pub struct RetrieveKeyshareData {
	pub nft_id: u32,
	pub auth_token: AuthenticationToken,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum RequesterType {
	OWNER,
	DELEGATEE,
	RENTEE,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RetrieveKeysharePacket {
	pub requester_address: sr25519::Public,
	pub requester_type: RequesterType,
	pub data: String, // TODO: Replace by "SecretData" JWT/JWS
	pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RemoveKeysharePacket {
	pub requester_address: sr25519::Public,
	pub nft_id: u32,
}

#[derive(Debug, PartialEq)]
pub enum KeyshareHolder {
	Owner(AccountId32),
	Delegatee(AccountId32),
	Rentee(AccountId32),
	NotFound,
}

impl VerificationError {
	/// Express the error in JSON format
	/// # Arguments
	/// * `call` - API call
	/// * `caller` - Caller of the API
	/// * `nft_id` - NFT ID
	/// * `enclave_id` - Enclave ID
	/// # Returns
	/// * `Json<Value>` - JSON format of the error
	pub fn express_verification_error(
		self,
		call: APICALL,
		caller: String,
		nft_id: u32,
		enclave_id: String,
	) -> (StatusCode, Json<Value>) {
		match self {
			// SIGNER SIGNATURE FORMAT
			VerificationError::INVALIDSIGNERSIG(e) => {
				let status = ReturnStatus::INVALIDSIGNERSIGNATURE;
				let description = format!(
					"TEE Key-share {call:?}: Invalid request signer signature format, {e:?} "
				);
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// DATA SIGNATURE FORMAT
			VerificationError::INVALIDDATASIG(e) => {
				let status = ReturnStatus::INVALIDDATASIGNATURE;
				let description =
					format!("TEE Key-share {call:?}: Invalid request data signature format, {e:?}");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// OWNER ADDRESS FORMAT
			VerificationError::INVALIDOWNERADDRESS => {
				let status = ReturnStatus::INVALIDOWNERADDRESS;
				let description = format!("TEE Key-share {call:?}: Invalid owner address format");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// SIGNER ADDRESS FORMAT
			VerificationError::INVALIDSIGNERADDRESS => {
				let status = ReturnStatus::INVALIDSIGNERADDRESS;
				let description = format!("TEE Key-share {call:?}: Invalid signer address format");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// VERIFY SIGNER TO BE SIGNED BY THE OWNER
			VerificationError::SIGNERVERIFICATIONFAILED => {
				let status = ReturnStatus::SIGNERSIGVERIFICATIONFAILED;
				let description = format!("TEE Key-share {call:?}: Signer signature verification failed, Signer is not approved by NFT owner");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// VERIFY SIGNER TO BE SIGNED BY THE OWNER
			VerificationError::DATAVERIFICATIONFAILED => {
				let status = ReturnStatus::DATASIGVERIFICATIONFAILED;
				let description =
					format!("TEE Key-share {call:?}: Data signature verification failed.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// AUTHENTICATION-TOKEN FORMAT
			VerificationError::INVALIDAUTHTOKEN => {
				let status = ReturnStatus::INVALIDAUTHTOKEN;
				let description =
					format!("TEE Key-share {call:?}: Invalid authentication-token format.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// NFTID FORMAT
			VerificationError::INVALIDNFTID => {
				let status = ReturnStatus::INVALIDNFTID;
				let description = format!(
					"TEE Key-share {call:?}: The nft-id is not a valid number or nft does not exist."
				);
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// EMPTY KEYSHARE
			VerificationError::INVALIDKEYSHARE => {
				let status = ReturnStatus::INVALIDKEYSHARE;
				let description = format!(
					"TEE Key-share {call:?}: The key-share is empty or not a valid string."
				);
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// VERIFY ONCHAIN NFTID TO BE OWNED BY SPECIFIED OWNER
			VerificationError::OWNERSHIPVERIFICATIONFAILED => {
				let status = ReturnStatus::OWNERSHIPVERIFICATIONFAILED;
				let description =
					format!("TEE Key-share {call:?}: The nft-id is not owned by this owner.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::UNAUTHORIZED,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			VerificationError::REQUESTERVERIFICATIONFAILED => {
				let status = ReturnStatus::REQUESTERVERIFICATIONFAILED;
				let description = format!(
					"TEE Key-share {call:?}: The requester is not either owner, delegatee or rentee."
				);
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// EPIRATION PERIOD OF SIGNER ACCOUNT  (AUTHENTICATION-TOKEN)
			VerificationError::EXPIREDSIGNER(e) => {
				let status = ReturnStatus::EXPIREDSIGNER;
				let description = format!("TEE Key-share {call:?}: The signer account has been expired or is not in valid range.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// EPIRATION PERIOD OF REQUEST DATA  (AUTHENTICATION-TOKEN)
			VerificationError::EXPIREDDATA(e) => {
				let status = ReturnStatus::EXPIREDREQUEST;
				let description = format!("TEE Key-share {call:?}: The request data field has been expired  or is not in valid range.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// IS NOT ENCRYPTED ENTITY
			VerificationError::IDISNOTSECRETNFT => {
				let status = ReturnStatus::IDISNOTASECRETNFT;
				let description =
					format!("TEE Key-share {call:?}: The nft-id is not a secret-nft.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// IS NOT ENCRYPTED ENTITY
			VerificationError::IDISNOTCAPSULE => {
				let status = ReturnStatus::IDISNOTACAPSULE;
				let description = format!("TEE Key-share {call:?}: The nft-id is not a capsule.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// IS NOT ENCRYPTED ENTITY
			VerificationError::NOTSYNCING => {
				let status = ReturnStatus::NOTSYNCING;
				let description = format!("TEE Key-share {call:?}: The nft is not in syncing mode.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::FORBIDDEN,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// NFT IS NOT IN SYNCED MODE TO RETRIEVE STORED KEYSHARES
			VerificationError::NOTSYNCED => {
				let status = ReturnStatus::NOTSYNCED;
				let description = format!("TEE Key-share {call:?}: The nft is not in synced mode.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::FORBIDDEN,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// PARSE DATA PACKET FAILED
			VerificationError::MALFORMATEDDATA => {
				let status = ReturnStatus::INVALIDDATAFORMAT;
				let description = format!("TEE Key-share {call:?}: Failed to parse data field.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			// PARSE SIGNER PACKET FAILED
			VerificationError::MALFORMATEDSIGNER => {
				let status = ReturnStatus::INVALIDSIGNERFORMAT;
				let description = format!("TEE Key-share {call:?}: Failed to parse Signer field.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			VerificationError::KEYSHAREISTOOSHORT => {
				let status = ReturnStatus::KEYSHAREISTOOSHORT;
				let description = format!(
					"TEE Key-share {call:?}: Secret-Share is too short, it is not secure enough."
				);
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},

			VerificationError::KEYSHAREISTOOLONG => {
				let status = ReturnStatus::KEYSHAREISTOOLONG;
				let description = format!("TEE Key-share {call:?}: Secret-Share is too long, it is not possible to store it.");
				info!("{}, requester : {}", description, caller);

				(
					StatusCode::BAD_REQUEST,
					Json(json! ({
						"status": status,
						"nft_id": nft_id,
						"enclave_id": enclave_id,
						"description": description,
					})),
				)
			},
		}
	}
}

/* ----------------------------------
		GET ONCHAIN DATA
----------------------------------*/

/// Fetch onchain owenrship of nft/capsule id
/// # Arguments
/// * `nft_id` - nft/capsule id
/// # Returns
/// * `KeyshareHolder` - KeyshareHolder enum
pub async fn get_onchain_delegatee_account(state: SharedState, nft_id: u32) -> KeyshareHolder {
	let delegatee_data = get_onchain_delegatee(state, nft_id).await;

	match delegatee_data {
		Some(account) => KeyshareHolder::Delegatee(account),
		None => KeyshareHolder::NotFound,
	}
}

/// Fetch onchain owenrship of nft/capsule id
/// # Arguments
/// * `nft_id` - nft/capsule id
/// # Returns
/// * `KeyshareHolder` - KeyshareHolder enum
pub async fn get_onchain_rentee_account(state: SharedState, nft_id: u32) -> KeyshareHolder {
	let rentee_data = get_onchain_rent_contract(state, nft_id).await;

	match rentee_data {
		Some(account) => KeyshareHolder::Rentee(account),
		None => KeyshareHolder::NotFound,
	}
}

/// Check nft/capsule owner/rentee/delegatee
/// # Arguments
/// * `requester_address` - requester address
/// * `nft_id` - nft/capsule id
/// * `owner` - nft/capsule owner
/// * `requester_type` - requester type
/// # Returns
/// * `bool` - true if requester is owner/rentee/delegatee
pub async fn verify_requester_type(
	state: SharedState,
	requester_address: String,
	nft_id: u32,
	owner: AccountId32,
	requester_type: RequesterType,
) -> bool {
	match AccountId32::from_str(&requester_address) {
		Ok(converted_requester_address) => match requester_type {
			RequesterType::OWNER => owner == converted_requester_address,

			RequesterType::DELEGATEE => match get_onchain_delegatee_account(state, nft_id).await {
				KeyshareHolder::Delegatee(delegatee) => delegatee == converted_requester_address,
				_ => false,
			},

			RequesterType::RENTEE => match get_onchain_rentee_account(state, nft_id).await {
				KeyshareHolder::Rentee(rentee) => rentee == converted_requester_address,
				_ => false,
			},
		},

		Err(_) => false,
	}
}

/* ----------------------------------
AUTHENTICATION TOKEN IMPLEMENTATION
----------------------------------*/
#[derive(Serialize, PartialEq, Debug)]
pub enum ValidationResult {
	Success,
	ErrorRpcCall,
	ExpiredBlockNumber,
	FutureBlockNumber,
	InvalidPeriod,
}

// Retrieving the stored Keyshare
impl AuthenticationToken {
	// TODO: use json canonicalization of JOSE/JWT encoder
	/// Serialize AuthenticationToken
	pub fn serialize(self) -> String {
		self.block_number.to_string() + "_" + &self.block_validation.to_string()
	}

	pub fn is_valid(&self, last_block_number: u32) -> ValidationResult {
		if last_block_number < self.block_number - MAX_BLOCK_VARIATION {
			// for finalization delay
			debug!(
				"last block number = {} < request block number = {}",
				last_block_number, self.block_number
			);
			return ValidationResult::ExpiredBlockNumber;
		}

		if self.block_validation > MAX_VALIDATION_PERIOD {
			// A finite validity period
			return ValidationResult::InvalidPeriod;
		}

		if last_block_number > self.block_number + self.block_validation + MAX_BLOCK_VARIATION {
			debug!(
				"last block number = {} > request block number = {} + validation_interval = {} + MAX_BLOCK_VARIATION = {}",
				last_block_number, self.block_number, self.block_validation, MAX_BLOCK_VARIATION
			);
			// validity period
			return ValidationResult::FutureBlockNumber;
		}

		ValidationResult::Success
	}
}

/* ----------------------------------
   SECRET-DATA IMPLEMENTATION
----------------------------------*/

// Retrieving the stored Keyshare
impl StoreKeyshareData {
	pub fn serialize(self) -> String {
		let keyshare_str = match String::from_utf8(self.keyshare) {
			Ok(s) => s,
			Err(e) => return format!("Error serializing keyshare data: {}", e),
		};
		format!("{}_{}_{}", self.nft_id, keyshare_str, self.auth_token.serialize())
	}
}

/* ----------------------------------
	STORE-PACKET IMPLEMENTATION
----------------------------------*/

impl StoreKeysharePacket {
	pub fn get_signer(&self) -> Result<Signer, VerificationError> {
		let mut signer = self.signer_address.clone();

		if signer.starts_with("<Bytes>") && signer.ends_with("</Bytes>") {
			signer = signer
				.strip_prefix("<Bytes>")
				.ok_or(VerificationError::MALFORMATEDSIGNER)?
				.strip_suffix("</Bytes>")
				.ok_or(VerificationError::MALFORMATEDSIGNER)?
				.to_string();
		}

		let parsed_data: Vec<&str> = if signer.contains('_') {
			signer.split('_').collect()
		} else {
			return Err(VerificationError::MALFORMATEDSIGNER);
		};

		if parsed_data.len() < 3 {
			return Err(VerificationError::MALFORMATEDSIGNER);
		}

		let account = sr25519::Public::from_ss58check(parsed_data[0])
			.map_err(|_| VerificationError::INVALIDSIGNERADDRESS)?;

		let block_num =
			parsed_data[1].parse::<u32>().map_err(|_| VerificationError::INVALIDAUTHTOKEN)?;

		let block_valid =
			parsed_data[2].parse::<u32>().map_err(|_| VerificationError::INVALIDAUTHTOKEN)?;

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
		let mut data = self.data.clone();

		if data.starts_with("<Bytes>") && data.ends_with("</Bytes>") {
			data = data
				.strip_prefix("<Bytes>")
				.ok_or(VerificationError::MALFORMATEDDATA)?
				.strip_suffix("</Bytes>")
				.ok_or(VerificationError::MALFORMATEDDATA)?
				.to_string();
		}

		let parsed_data: Vec<&str> = if data.contains('_') {
			data.split('_').collect()
		} else {
			return Err(VerificationError::MALFORMATEDDATA);
		};

		if parsed_data.len() != 4 {
			return Err(VerificationError::MALFORMATEDDATA);
		}

		let nft_id = parsed_data[0].parse::<u32>().map_err(|_| VerificationError::INVALIDNFTID)?;

		let keyshare = if !parsed_data[1].is_empty() {
			parsed_data[1].as_bytes().to_vec()
		} else {
			return Err(VerificationError::INVALIDKEYSHARE);
		};

		let keyshare_size = keyshare.len() as u16;
		if keyshare_size < 16 {
			return Err(VerificationError::KEYSHAREISTOOSHORT);
		}

		if keyshare_size > 3000 {
			return Err(VerificationError::KEYSHAREISTOOLONG);
		}

		let block_number =
			parsed_data[2].parse::<u32>().map_err(|_| VerificationError::INVALIDAUTHTOKEN)?;

		let block_validation =
			parsed_data[3].parse::<u32>().map_err(|_| VerificationError::INVALIDAUTHTOKEN)?;

		Ok(StoreKeyshareData {
			nft_id,
			keyshare,
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
	pub fn verify_signer(&self, last_block_number: u32) -> Result<bool, VerificationError> {
		let signer = match self.get_signer() {
			Ok(pk) => pk,
			Err(_) => return Err(VerificationError::INVALIDSIGNERADDRESS),
		};

		let verify = signer.auth_token.is_valid(last_block_number);
		match verify {
			ValidationResult::Success => debug!("Signer auth-token is valid"),
			_ => return Err(VerificationError::EXPIREDSIGNER(verify)),
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
	pub fn verify_data(&self) -> Result<bool, VerificationError> {
		let signer = match self.get_signer() {
			Ok(signer) => signer,
			Err(e) => return Err(e),
		};

		let packetsig = match self.parse_signature("owner") {
			Ok(sig) => sig,
			Err(e) => return Err(VerificationError::INVALIDDATASIG(e)),
		};

		let result = sr25519::Pair::verify(&packetsig, self.data.clone(), &signer.account);

		Ok(result)
	}

	/// Verify store request
	pub async fn verify_store_request(
		&self,
		state: SharedState,
		nft_type: &str,
	) -> Result<StoreKeyshareData, VerificationError> {
		let shared_state_read = state.read().await;
		let last_block_number = shared_state_read.get_current_block();
		drop(shared_state_read);

		match self.verify_signer(last_block_number) {
			Ok(true) => match self.verify_data() {
				Ok(true) => {
					let parsed_data = match self.parse_store_data() {
						Ok(parsed_keyshare) => parsed_keyshare,
						Err(e) => return Err(e),
					};

					let onchain_nft_data =
						match get_onchain_nft_data(state.clone(), parsed_data.nft_id).await {
							Some(nftdata) => nftdata,
							_ => return Err(VerificationError::INVALIDNFTID),
						};

					let nft_status = onchain_nft_data.state;

					if nft_type == "secret-nft" {
						if !nft_status.is_secret {
							return Err(VerificationError::IDISNOTSECRETNFT);
						}

						if !nft_status.is_syncing_secret {
							return Err(VerificationError::NOTSYNCING);
						}
					}

					if nft_type == "capsule" {
						if !nft_status.is_capsule {
							return Err(VerificationError::IDISNOTCAPSULE);
						}

						if !nft_status.is_syncing_capsule {
							return Err(VerificationError::NOTSYNCING);
						}
					}

					let verify = parsed_data.auth_token.clone().is_valid(last_block_number);
					match verify {
						ValidationResult::Success => debug!("Signer auth-token is valid"),
						_ => return Err(VerificationError::EXPIREDDATA(verify)),
					}

					if verify_requester_type(
						state,
						self.owner_address.to_string(),
						parsed_data.nft_id,
						onchain_nft_data.owner,
						RequesterType::OWNER,
					)
					.await
					{
						Ok(parsed_data)
					} else {
						Err(VerificationError::OWNERSHIPVERIFICATIONFAILED)
					}
				},
				Ok(false) => Err(VerificationError::DATAVERIFICATIONFAILED),
				Err(e) => Err(e),
			},

			// INVALID DATA SIGNATURE
			Ok(false) => Err(VerificationError::SIGNERVERIFICATIONFAILED),

			Err(e) => Err(e),
		}
	}

	// SIGNATURE ONLY VERIFICATION
	#[allow(dead_code)]
	pub fn verify_free_store_request(
		&self,
		last_block_number: u32,
	) -> Result<StoreKeyshareData, VerificationError> {
		match self.verify_signer(last_block_number) {
			Ok(true) => {
				let data = match self.parse_store_data() {
					Ok(sec) => sec,
					Err(e) => return Err(e),
				};

				match self.verify_data() {
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

/* ----------------------------------
	RETRIEVE-PACKET IMPLEMENTATION
----------------------------------*/

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
				.ok_or(VerificationError::MALFORMATEDDATA)?
				.strip_suffix("</Bytes>")
				.ok_or(VerificationError::MALFORMATEDDATA)?
				.to_string();
		}

		let parsed_data: Vec<&str> = if data.contains('_') {
			data.split('_').collect()
		} else {
			return Err(VerificationError::MALFORMATEDDATA);
		};

		if parsed_data.len() != 3 {
			return Err(VerificationError::MALFORMATEDDATA);
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

	// VERIFY KEYSHARE DATA : TOKEN & SIGNATURE
	pub fn verify_data(&self, last_block_number: u32) -> Result<bool, VerificationError> {
		let data = match self.parse_retrieve_data() {
			Ok(sec) => sec,
			Err(e) => return Err(e),
		};

		let verify = data.auth_token.is_valid(last_block_number);
		match verify {
			ValidationResult::Success => debug!("Data auth-token is valid"),
			_ => return Err(VerificationError::EXPIREDDATA(verify)),
		}

		let sig = match self.parse_signature() {
			Ok(sig) => sig,
			Err(e) => return Err(VerificationError::INVALIDSIGNERSIG(e)),
		};

		let result = sr25519::Pair::verify(&sig, self.data.clone(), &self.requester_address);

		Ok(result)
	}

	/// Verify the requester is the owner of the NFT
	pub async fn verify_retrieve_request(
		&self,
		state: SharedState,
		nft_type: &str,
	) -> Result<RetrieveKeyshareData, VerificationError> {
		let shared_state_read = state.read().await;
		let last_block_number = shared_state_read.get_current_block();
		drop(shared_state_read);

		match self.verify_data(last_block_number) {
			Ok(true) => {
				let parsed_data = match self.parse_retrieve_data() {
					Ok(parsed) => parsed,
					Err(e) => return Err(e),
				};

				let onchain_nft_data =
					match get_onchain_nft_data(state.clone(), parsed_data.nft_id).await {
						Some(nftdata) => nftdata,
						_ => return Err(VerificationError::INVALIDNFTID),
					};

				let nft_status = onchain_nft_data.state;

				if nft_type == "secret-nft" {
					if !nft_status.is_secret {
						return Err(VerificationError::IDISNOTSECRETNFT);
					}

					if nft_status.is_syncing_secret {
						return Err(VerificationError::NOTSYNCED);
					}
				}

				if nft_type == "capsule" {
					if !nft_status.is_capsule {
						return Err(VerificationError::IDISNOTCAPSULE);
					}

					if nft_status.is_syncing_capsule {
						return Err(VerificationError::NOTSYNCED);
					}
				}

				let verify = parsed_data.auth_token.clone().is_valid(last_block_number);
				match verify {
					ValidationResult::Success => debug!("Data auth-token is valid"),
					_ => return Err(VerificationError::EXPIREDDATA(verify)),
				}

				if verify_requester_type(
					state,
					self.requester_address.to_string(),
					parsed_data.nft_id,
					onchain_nft_data.owner,
					self.requester_type,
				)
				.await
				{
					Ok(parsed_data)
				} else {
					Err(VerificationError::REQUESTERVERIFICATIONFAILED)
				}
			},
			// INVALID DATA SIGNATURE
			Ok(false) => Err(VerificationError::SIGNERVERIFICATIONFAILED),

			Err(e) => Err(e),
		}
	}

	// VERIFTY FREE RETRIVE REQUEST
	#[allow(dead_code)]
	pub async fn verify_free_retrieve_request(
		&self,
		last_block_number: u32,
	) -> Result<RetrieveKeyshareData, VerificationError> {
		let data = match self.parse_retrieve_data() {
			Ok(sec) => sec,
			Err(e) => return Err(e),
		};

		match self.verify_data(last_block_number) {
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
		HELPER FUNCTIONS
	---------------------- */
	/// Generate a random string of a given length
	async fn generate_store_request(nftid: u32) -> StoreKeysharePacket {
		let current_block_number = get_current_block_number_new_api().await.unwrap();

		let owner = sr25519::Pair::from_phrase(
			"theme affair risk blue world review hazard social arrow usage unveil surge",
			None,
		)
		.unwrap()
		.0;
		let signer = sr25519::Pair::from_phrase(
			"cover fossil blouse ignore embark elbow blush awful mushroom wood deny common",
			None,
		)
		.unwrap()
		.0;

		let signer_address =
			format!("{}_{}_10", signer.public().to_ss58check(), current_block_number);
		let signersig = owner.sign(signer_address.as_bytes());
		let data = format!(
			"{}_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_{}_10",
			nftid, current_block_number
		);
		let signature = signer.sign(data.as_bytes());

		let packet = StoreKeysharePacket {
			owner_address: owner.public(),
			signer_address,
			signersig: format!("{}{:?}", "0x", signersig),
			data,
			signature: format!("{}{:?}", "0x", signature),
		};

		println!("StoreKeysharePacket = {}\n", serde_json::to_string_pretty(&packet).unwrap());

		packet
	}

	/// Generate a random string of a given length
	async fn generate_retrieve_request(nftid: u32) -> RetrieveKeysharePacket {
		let current_block_number = get_current_block_number_new_api().await.unwrap();

		let owner = sr25519::Pair::from_phrase(
			"theme affair risk blue world review hazard social arrow usage unveil surge",
			None,
		)
		.unwrap()
		.0;

		let data = format!("{}_{}_10", nftid, current_block_number);
		let signature = owner.sign(data.as_bytes());
		let packet = RetrieveKeysharePacket {
			requester_address: owner.public(),
			requester_type: RequesterType::OWNER,
			data,
			signature: format!("{}{:?}", "0x", signature),
		};

		println!("RetrieveKeysharePacket = {}\n", serde_json::to_string_pretty(&packet).unwrap());

		packet
	}

	/// Generate a random string of a given length
	async fn generate_remove_request(nftid: u32) -> RemoveKeysharePacket {
		let signer = sr25519::Pair::from_phrase(
			"steel announce garden guilt direct give morning gadget milk census poem faith",
			None,
		)
		.unwrap()
		.0;

		let requester_address = signer.public();

		let packet = RemoveKeysharePacket {
			requester_address, // Because anybody can ask to remove burnt data
			nft_id: nftid,
		};

		println!("RemoveKeysharePacket = {}\n", serde_json::to_string_pretty(&packet).unwrap());

		packet
	}

	/* ----------------------
		 PARSING
	---------------------- */
	#[tokio::test]
	async fn parse_data_from_sdk_test() {
		let packet_sdk = StoreKeysharePacket {
			owner_address: sr25519::Public::from_slice(&[0u8; 32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			data: "163_1234567890abcdef_1000_15".to_string(),
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};

		// Signed in SDK
		let data = packet_sdk.parse_store_data().unwrap();

		assert_eq!(data.nft_id, 163);
		assert_eq!(data.keyshare, b"1234567890abcdef");
		assert_eq!(data.auth_token.block_number, 1000);
		assert_eq!(data.auth_token.block_validation, 15);
	}

	#[tokio::test]
	async fn parse_data_from_polkadotjs_test() {
		let packet_polkadotjs = StoreKeysharePacket {
			owner_address: sr25519::Public::from_slice(&[0u8; 32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			data: "<Bytes>163_1234567890abcdef_1000_15</Bytes>".to_string(),
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};
		// Signed in Polkadot.JS
		let data = packet_polkadotjs.parse_store_data().unwrap();

		assert_eq!(data.nft_id, 163);
		assert_eq!(data.keyshare, b"1234567890abcdef");
		assert_eq!(data.auth_token.block_number, 1000);
		assert_eq!(data.auth_token.block_validation, 15);
	}

	#[tokio::test]
	async fn get_public_key_test() {
		let packet_sdk = StoreKeysharePacket {
			owner_address: sr25519::Public::from_ss58check(
				"5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6",
			)
			.unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			data: "xxx".to_string(),
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
			data: "xxx".to_string(),
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
		let current_block_number = get_current_block_number_new_api().await.unwrap();
		let mut packet = generate_store_request(1300).await;

		// correct
		assert!(packet.verify_data().unwrap());

		// changed data error
		packet.data = format!(
			"324_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-O)_{}_10",
			current_block_number
		);
		assert!(!packet.verify_data().unwrap());

		// changed signer error
		packet.signer_address =
			format!("5ChoJxKns4yyHeZg38U2hc8WYQ691oHzPJZtnayZXFyXvXET_{}_10", current_block_number);
		packet.data = format!(
			"324_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_{}_10",
			current_block_number
		);
		assert!(!packet.verify_data().unwrap());

		// changed signature error
		packet.owner_address =
			sr25519::Public::from_ss58check("5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy")
				.unwrap();
		packet.signature = "0xa64400b64bed9b77a59e5a5f1d2e82489fcf20fcc5ff563d755432ffd2ef5c57021478051f9f93e8448fa4cb4c4900d406c263588898963d3d7960a3a5c16485".to_string();
		assert!(!packet.verify_data().unwrap());
	}

	#[tokio::test]
	async fn verify_polkadotjs_request_test() {
		let current_block_number = get_current_block_number_new_api().await.unwrap();

		let owner = sr25519::Pair::generate().0;
		let signer = sr25519::Pair::generate().0;
		let signer_address = format!(
			"<Bytes>{}_{}_10</Bytes>",
			&signer.public().to_ss58check(),
			current_block_number
		);
		let signersig = owner.sign(signer_address.as_bytes());
		let data = format!(
			"<Bytes>324_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_{}_10</Bytes>",
			current_block_number
		);
		let signature = signer.sign(data.as_bytes());

		let packet = StoreKeysharePacket {
			owner_address: owner.public(),
			signer_address,
			signersig: format!("{}{:?}", "0x", signersig),
			data,
			signature: format!("{}{:?}", "0x", signature),
		};

		let correct_data = StoreKeyshareData {
			nft_id: 324,
			keyshare: "thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)".as_bytes().to_vec(),
			auth_token: AuthenticationToken {
				block_number: current_block_number,
				block_validation: 10,
			},
		};

		// correct
		assert_eq!(packet.verify_free_store_request(current_block_number).unwrap(), correct_data);
	}

	#[tokio::test]
	async fn verify_signer_request_test() {
		let current_block_number = get_current_block_number_new_api().await.unwrap();
		// Test
		let owner = sr25519::Pair::generate().0;
		let signer = sr25519::Pair::generate().0;

		let signer_address =
			format!("{}_{}_10", signer.public().to_ss58check(), current_block_number);
		let signersig = owner.sign(signer_address.as_bytes());
		let data = format!(
			"494_thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)_{}_10",
			current_block_number
		);
		let signature = signer.sign(data.as_bytes());

		let mut packet = StoreKeysharePacket {
			owner_address: owner.public(),
			signer_address: signer_address.clone(),
			signersig: format!("{}{:?}", "0x", signersig),
			data,
			signature: format!("{}{:?}", "0x", signature),
		};

		let correct_data = StoreKeyshareData {
			nft_id: 494,
			keyshare: "thisIsMySecretDataWhichCannotContainAnyUnderScore(:-P)".as_bytes().to_vec(),
			auth_token: AuthenticationToken {
				block_number: current_block_number,
				block_validation: 10,
			},
		};

		// correct
		assert_eq!(packet.verify_free_store_request(current_block_number).unwrap(), correct_data);

		// changed owner error
		packet.owner_address =
			sr25519::Public::from_ss58check("5DLgQdhNz8B7RTKKMRCDwJWWbqu5FRYsLgJivLhVaYEsCpin")
				.unwrap();
		assert_eq!(
			packet.verify_free_store_request(current_block_number).unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// changed signer error
		packet.owner_address = owner.public();
		packet.signer_address = format!(
			"{}_{}_10",
			sr25519::Pair::generate().0.public().to_ss58check(),
			current_block_number
		);
		assert_eq!(
			packet.verify_free_store_request(current_block_number).unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// changed signer signature error
		packet.signer_address =
			format!("{}_{}_10", signer.public().to_ss58check(), current_block_number);
		packet.signersig = "0xa4f331ec6c6197a95122f171fbbb561f528085b2ca5176d676596eea03669718a7047cd29db3da4f5c48d3eb9df5648c8b90851fe9781dfaa11aef0eb1e6b88a".to_string();
		assert_eq!(
			packet.verify_free_store_request(current_block_number).unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// expired signer error
		let expired_signer_address =
			format!("{}_{}_10", signer.public().to_ss58check(), current_block_number - 13);
		let expired_signersig = owner.sign(signer_address.as_bytes());

		packet.signer_address = expired_signer_address;
		packet.signersig = format!("{}{:?}", "0x", expired_signersig);

		assert_eq!(
			packet.verify_free_store_request(current_block_number).unwrap_err(),
			VerificationError::EXPIREDSIGNER(ValidationResult::ExpiredBlockNumber)
		);
	}
}
