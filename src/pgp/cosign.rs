use std::io::Read;

use anyhow::Result;

use sigstore::crypto::{
	signing_key::{ecdsa::ECDSAKeys, SigStoreKeyPair},
	CosignVerificationKey, SigStoreSigner, Signature, SigningScheme,
};

// Runtime: Inside Enclave
const BINARYFILE: &str = "./bin/sgx_server";
const BINARYSIG: &str = "./bin/sgx_server.sig";

// Compile-time : Source Code
const _PASSWORD: &str = "Xxxxxxxxxx";
const ECDSA_P256_ASN1_PUBLIC_PEM: &[u8] = include_bytes!("../../credentials/keys/cosign.pub");
const _ECDSA_P256_ASN1_ENCRYPTED_PRIVATE_PEM: &[u8] =
	include_bytes!("../../credentials/keys/cosign.key");

fn _import_skey() -> SigStoreSigner {
	// Imported encrypted PEM encoded private key as SigStoreKeyPair.
	let _key_pair = SigStoreKeyPair::from_encrypted_pem(
		_ECDSA_P256_ASN1_ENCRYPTED_PRIVATE_PEM,
		_PASSWORD.as_bytes(),
	)
	.unwrap();

	// Imported encrypted PEM encoded private key as ECDSAKeys.
	let ecdsa_key_pair =
		ECDSAKeys::from_encrypted_pem(_ECDSA_P256_ASN1_ENCRYPTED_PRIVATE_PEM, _PASSWORD.as_bytes())
			.unwrap();

	// Converted ECDSAKeys to SigStoreSigner.
	let ecdsa_signer_pair = ecdsa_key_pair.to_sigstore_signer().unwrap();

	ecdsa_signer_pair
}

fn import_vkey() -> CosignVerificationKey {
	// Imported PEM encoded public key as CosignVerificationKey using ECDSA_P256_ASN1_PUBLIC_PEM as verification algorithm.
	let verification_key =
		CosignVerificationKey::from_pem(ECDSA_P256_ASN1_PUBLIC_PEM, &SigningScheme::default())
			.unwrap();

	verification_key
}

pub fn verify() -> Result<bool, anyhow::Error> {
	let verification_key = import_vkey();
	let mut signed_data = Vec::<u8>::new();
	let mut signature_data = Vec::<u8>::new();

	let mut f = match std::fs::File::open(BINARYFILE) {
		Ok(f) => f,
		Err(e) => {
			tracing::error!("can not open binary file, {}", e);
			return Err(e.into());
		},
	};

	match f.read(&mut signed_data) {
		Ok(_) => tracing::debug!("binary file read complete."),
		Err(e) => {
			tracing::error!("can not read binary file, {}", e);
			return Err(e.into());
		},
	}

	let mut f = match std::fs::File::open(BINARYSIG) {
		Ok(f) => f,
		Err(e) => {
			tracing::error!("can not open binary signature file, {}", e);
			return Err(e.into());
		},
	};

	match f.read(&mut signature_data) {
		Ok(_) => tracing::debug!("binary signature file read complete."),
		Err(e) => {
			tracing::error!("can not read binary signature file, {}", e);
			return Err(e.into());
		},
	}

	//Verifying the signature of the binary file
	match verification_key.verify_signature(Signature::Raw(&signature_data), &signed_data) {
		Ok(_) => {
			tracing::info!("Binary file Verification Succeeded.");
			Ok(true)
		},

		Err(e) => {
			tracing::error!("Binary file signature verification failed, {}", e);
			Ok(false)
		},
	}
}
