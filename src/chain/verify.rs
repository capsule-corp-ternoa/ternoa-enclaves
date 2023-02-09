use hex::FromHex;
use std::str::FromStr;

use sp_core::{sr25519, ByteArray, Pair};
use subxt::utils::AccountId32;

use serde::{Deserialize, Serialize};

use crate::chain::chain::{get_current_block_number, get_onchain_data};

/* **********************
  DATA STRUCTURES
********************** */

#[derive(Debug)]
pub enum SecretError {
	InvalidSignature,
	InvalidOwner,
	InvalidSigner,
}

#[derive(Serialize, PartialEq)]
pub enum ReturnStatus {
	STORESUCCESS,
	RETRIEVESUCCESS,
	REMOVESUCCESS,

	INVALIDSIGNERSIGNATURE,
	INVALIDOWNERSIGNATURE,

	INVALIDOWNER,

	EXPIREDSIGNER,
	EXPIREDREQUEST,

	NFTIDEXISTS,
	NFTIDNOTEXIST,

	CAPSULEIDNOTEXIST,

	DATABASEFAILURE,
	ORACLEFAILURE,

	NFTSECRETNOTACCESSIBLE,
	NFTSECRETNOTREADABLE,

	CAPSULESECRETNOTACCESSIBLE,
	CAPSULESECRETNOTREADABLE,

	NFTNOTBURNT,

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
	INVALIDSIGNERACCOUNT,

	EXPIREDSIGNER,
	EXPIREDSECRET,
}

// Validity time of Secret Data
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
}

// Secret Data structure
#[derive(Clone, Debug, PartialEq)]
pub struct SecretData {
	pub nft_id: u32,
	pub data: Vec<u8>,
	pub auth_token: AuthenticationToken,
}

// Packet-signer and validity of it
#[derive(Clone)]
pub struct Signer {
	account: sr25519::Public,
	block_validation: u32,
}

#[derive(Deserialize, Clone)]
pub struct SecretPacket {
	pub owner_address: sr25519::Public,

	// Signed by owner
	signer_address: String,
	signersig: String,

	// Signed by signer
	pub secret_data: String, // TODO: Replace by "SecretData" JWT/JWS
	pub signature: String,
}

#[derive(Debug, PartialEq)]
pub enum SecretOwner {
	Owner(AccountId32),
	NotFound,
}

// Fetch onchain owenrship of nft/capsule id
pub async fn get_onchain_owner(nft_id: u32) -> SecretOwner {
	let data = get_onchain_data(nft_id).await;

	let owner = match data {
		Some(capsule_data) => SecretOwner::Owner(capsule_data.owner),
		None => SecretOwner::NotFound,
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
		None => {
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
			}
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
   SIGNER IMPLEMENTATION
----------------------------------*/

// Check signer account expiration block-number
impl Signer {
	pub async fn is_valid(self) -> bool {
		self.block_validation > get_current_block_number().await
	}
}

/* ----------------------------------
   SECRET-DATA IMPLEMENTATION
----------------------------------*/

// Retrieving the stored secret
impl SecretData {
	// TODO: use json canonicalization of JOSE/JWT encoder
	pub fn serialize(self) -> String {
		self.nft_id.to_string() + "_" + &String::from_utf8(self.data).unwrap()
	}

	pub async fn is_valid(self) -> bool {
		let last_block_number = get_current_block_number().await;
		(last_block_number > self.auth_token.block_number)
			&& (last_block_number < self.auth_token.block_number + self.auth_token.block_validation)
	}
}

/* ----------------------------------
SECRET-PACKET IMPLEMENTATION
----------------------------------*/

impl SecretPacket {
	// Signer string to public key
	pub fn get_signer(&self) -> Result<Signer, ()> {
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
			return Err(());
		};

		Ok(Signer {
			account: sr25519::Public::from_str(parsed_data[0]).unwrap(),
			block_validation: parsed_data[1].parse::<u32>().unwrap(),
		})
	}

	// TODO: use json canonicalization of JOSE/JWT decoder
	pub fn parse_secret(&self) -> SecretData {
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
	pub fn get_owner(&self) -> Result<sr25519::Public, ()> {
		sr25519::Public::from_slice(self.owner_address.clone().as_slice())
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

		if !signer.is_valid().await {
			return Err(VerificationError::EXPIREDSIGNER);
		}

		let signersig = match self.parse_signature("signer") {
			Ok(sig) => sig,
			Err(e) => return Err(VerificationError::INVALIDSIGNERSIG(e)),
		};

		let result =
			sr25519::Pair::verify(&signersig, self.signer_address.clone(), &self.owner_address);
		Ok(result)
	}

	// Verify secret data
	pub async fn verify_secret(&self) -> Result<bool, VerificationError> {
		let signer = self.get_signer().unwrap();

		let packetsig = match self.parse_signature("owner") {
			Ok(sig) => sig,
			Err(e) => {
				return Err(VerificationError::INVALIDOWNERSIG(e));
			},
		};

		let secret = self.parse_secret();
		if !secret.is_valid().await {
			return Err(VerificationError::EXPIREDSECRET);
		}

		let result = sr25519::Pair::verify(&packetsig, self.secret_data.clone(), &signer.account);

		Ok(result)
	}

	// Check nft/capsule owner
	pub async fn check_capsule_ownership(&self) -> bool {
		let capsule_owner = get_onchain_owner(self.parse_secret().nft_id).await;
		match capsule_owner {
			SecretOwner::Owner(owner) => owner == self.owner_address.into(),
			SecretOwner::NotFound => false,
		}
	}

	pub async fn verify_request(&self) -> Result<SecretData, VerificationError> {
		match self.verify_signer().await {
			// TODO: For burnt nft/capsule "check ownership" will fail!
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
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;
	use sp_keyring::AccountKeyring;
	use tracing::info;

	/* TODO: This test can not pass in workflow action, without verified account and nft_id
	#[tokio::test]
	async fn get_capsule_owner_test() {
		let address = AccountId32::from(
			sr25519::Public::from_ss58check("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6")
				.unwrap(),
		);
		let nft_id = 10;
		let owner = match get_capsule_owner(nft_id).await {
			SecretOwner::Owner(addr) => addr,
			SecretOwner::NotFound => panic!("Test erros, nft_id is not available, check your chain."),
		};
		let other = match get_capsule_owner(nft_id + 100).await {
			SecretOwner::Owner(addr) => addr,
			SecretOwner::NotFound => panic!("Test erros, nft_id is not available, check your chain."),
		};
		let unknown = get_capsule_owner(10_000).await;

		assert_eq!(owner, address); // Same Capsule match Owner
		assert_ne!(other, address); // Different Capsules, (probably) diffetent owners
		assert_ne!(owner, AccountKeyring::Alice.to_raw_public().into()); // Unauthorized random owner
		assert_eq!(unknown, SecretOwner::NotFound); // Unavailable Capsule
	}
	*/

	/* ----------------------
		 PARSING
	---------------------- */
	#[tokio::test]
	async fn parse_secret_from_sdk_test() {
		let secret_packet_sdk: SecretPacket = SecretPacket {
			owner_address: sr25519::Public::from_slice(&[0u8; 32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			secret_data: "163_1234567890abcdef_1000_10000".to_string(),
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};

		// Signed in SDK
		let secret_data = secret_packet_sdk.parse_secret();

		assert_eq!(secret_data.nft_id, 163);
		assert_eq!(secret_data.data, b"1234567890abcdef");
		assert_eq!(secret_data.auth_token.block_number, 1000);
		assert_eq!(secret_data.auth_token.block_validation, 10000);
	}

	#[tokio::test]
	async fn parse_secret_from_polkadotjs_test() {
		let secret_packet_polkadotjs: SecretPacket = SecretPacket {
			owner_address: sr25519::Public::from_slice(&[0u8; 32]).unwrap(),
			signer_address: sr25519::Public::from_slice(&[1u8; 32]).unwrap().to_string(),
			secret_data: "<Bytes>163_1234567890abcdef_1000_10000</Bytes>".to_string(),
			signature: "xxx".to_string(),
			signersig: "xxx".to_string(),
		};
		// Signed in Polkadot.JS
		let secret_data = secret_packet_polkadotjs.parse_secret();

		assert_eq!(secret_data.nft_id, 163);
		assert_eq!(secret_data.data, b"1234567890abcdef");
		assert_eq!(secret_data.auth_token.block_number, 1000);
		assert_eq!(secret_data.auth_token.block_validation, 10000);
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

		// missing 0x prefix
		secret_packet_sdk.signature = "42bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		let sig = secret_packet_sdk.parse_signature("owner").unwrap_err();
		assert_eq!(sig, SignatureError::PREFIXERROR);

		// Incorrect Length
		secret_packet_sdk.signature = "0x2bb4b16fb9d6f1a7c902edac7d511679827b262cb1d0e5e5fd5d3af6c3dc715ef4c5e1810056db80bfa866c207b786d79987242608ca6944e857772cb1b858b".to_string();
		let sig = secret_packet_sdk.parse_signature("owner").unwrap_err();
		assert_eq!(sig, SignatureError::LENGHTERROR);
	}

	/* ----------------------
		 VERIFICATION
	---------------------- */

	#[tokio::test]
	async fn verify_secret_test() {
		let mut secret_packet = SecretPacket {
			owner_address: <sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check("5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy").unwrap(),
			signer_address: "<Bytes>5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy_200000</Bytes>".to_string(),
			signersig: "0xc889f814d8811617cea97b23227b300fc900f3466f1587aa4e14e1aa3ffe3b2fead469644dad7e5cc89fb36c96bdc144ec5f4f1b5b9b96f545b10af1d3e8c282".to_string(),
			secret_data: "<Bytes>163_1234567890abcdef_120000_100000</Bytes>".to_string(), 
			signature: "0xa64400b64bed9b77a59e5a5f1d2e82489fcf20fcc5ff563d755432ffd2ef5c57021478051f9f93e8448fa4cb4c4900d406c263588898963d3d7960a3a5c16484".to_string(),
		};

		// correct
		assert_eq!(secret_packet.verify_secret().await.unwrap(), true);

		// changed secret error
		secret_packet.secret_data = "<Bytes>163_1234567890abcdee_120000_100000</Bytes>".to_string();
		assert_eq!(secret_packet.verify_secret().await.unwrap(), false);

		// changed signer error
		secret_packet.signer_address =
			"<Bytes>5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY_200000</Bytes>".to_string();
		secret_packet.secret_data = "<Bytes>163_1234567890abcdef_120000_100000</Bytes>".to_string();
		assert_eq!(secret_packet.verify_secret().await.unwrap(), false);

		// changed signature error
		secret_packet.owner_address =
			<sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check(
				"5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",
			)
			.unwrap();
		secret_packet.signature = "0xa64400b64bed9b77a59e5a5f1d2e82489fcf20fcc5ff563d755432ffd2ef5c57021478051f9f93e8448fa4cb4c4900d406c263588898963d3d7960a3a5c16485".to_string();
		assert_eq!(secret_packet.verify_secret().await.unwrap(), false);

		// expired secret error
		secret_packet.secret_data = "<Bytes>163_1234567890abcdee_120000_1000</Bytes>".to_string();
		secret_packet.signature = "0x2879d6c3f63c108875219c67ce443c823c0a51b590da0aba4441c239f307354a8cbb983d9200bf67079b38c348b114d6a98d3b35cc8b4a20b4711e0e0a3e0582".to_string();
		assert_eq!(
			secret_packet.verify_secret().await.unwrap_err(),
			VerificationError::EXPIREDSECRET
		);
	}

	#[tokio::test]
	async fn verify_request_test() {
		let mut secret_packet = SecretPacket {
			owner_address: <sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check("5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy").unwrap(),
			signer_address: "<Bytes>5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy_200000</Bytes>".to_string(),
			signersig: "0xa09ceb432262a7d148869475de27e1678caa796da754a4313ccce57a5e409c0ba7bd1f5b6d9babed2686632a0ba14673bfd5ae7df7026a1b7a766bfdf172a688".to_string(),
			secret_data: "<Bytes>163_1234567890abcdef_120000_100000</Bytes>".to_string(), 
			signature: "0xa64400b64bed9b77a59e5a5f1d2e82489fcf20fcc5ff563d755432ffd2ef5c57021478051f9f93e8448fa4cb4c4900d406c263588898963d3d7960a3a5c16484".to_string(),
		};

		let correct_secret_data = SecretData {
			nft_id: 163,
			data: "1234567890abcdef".as_bytes().to_vec(),
			auth_token: AuthenticationToken { block_number: 120000, block_validation: 100000 },
		};

		// correct
		assert_eq!(secret_packet.verify_request().await.unwrap(), correct_secret_data);

		// changed owner error
		secret_packet.owner_address =
			<sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check(
				"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
			)
			.unwrap();
		assert_eq!(
			secret_packet.verify_request().await.unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// changed signer error
		secret_packet.owner_address =
			<sr25519::Public as sp_core::crypto::Ss58Codec>::from_ss58check(
				"5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",
			)
			.unwrap();
		secret_packet.signer_address =
			"<Bytes>5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY_200000</Bytes>".to_string();
		secret_packet.secret_data = "<Bytes>163_1234567890abcdef_120000_100000</Bytes>".to_string();
		assert_eq!(
			secret_packet.verify_request().await.unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// changed signer signature error
		secret_packet.signature = "0xa64400b64bed9b77a59e5a5f1d2e82489fcf20fcc5ff563d755432ffd2ef5c57021478051f9f93e8448fa4cb4c4900d406c263588898963d3d7960a3a5c16485".to_string();
		assert_eq!(
			secret_packet.verify_request().await.unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);

		// expired signer error
		secret_packet.secret_data = "<Bytes>163_1234567890abcdee_120000_1000</Bytes>".to_string();
		secret_packet.signature = "0x8664ed717bbc787df3344567a7bcbcee9c712f98862d5e1a7ce7956537e32b4fe675073d3937ad1983245f340aeba8aaf29f16a5d63685b51024e4452740828a".to_string();
		assert_eq!(
			secret_packet.verify_request().await.unwrap_err(),
			VerificationError::SIGNERVERIFICATIONFAILED
		);
	}
}
