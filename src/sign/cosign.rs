use anyhow::Result;

use sigstore::crypto::{
	signing_key::{ecdsa::ECDSAKeys, SigStoreKeyPair},
	CosignVerificationKey, SigStoreSigner, Signature, SigningScheme,
};
use tracing::error;

use crate::servers::binary_check::downloader;

fn _import_skey(path: &str, pass: &str) -> SigStoreSigner {
	// Imported encrypted PEM encoded private key as SigStoreKeyPair.
	let ecdsa_p256_asn1_encrypted_private_pem = std::fs::read(path).unwrap();

	let _key_pair = SigStoreKeyPair::from_encrypted_pem(
		&ecdsa_p256_asn1_encrypted_private_pem,
		pass.as_bytes(),
	)
	.unwrap();

	// Imported encrypted PEM encoded private key as ECDSAKeys.
	let ecdsa_key_pair =
		ECDSAKeys::from_encrypted_pem(&ecdsa_p256_asn1_encrypted_private_pem, pass.as_bytes())
			.unwrap();

	// Converted ECDSAKeys to SigStoreSigner.

	ecdsa_key_pair.to_sigstore_signer().unwrap()
}

fn import_vkey() -> Result<CosignVerificationKey, anyhow::Error> {
	// Production
	let url = "https://gist.githubusercontent.com/zorvan/46b26ff51b27590683ddaf70c0ea9dac/raw/2b437edaa808b79f2e7768cde9085150b2f10a32/cosign.pub";
	let get_pub = match downloader(url) {
		Ok(data) => data,
		Err(e) => {
			let message = format!("error retrieving public key from ternoa github {}", e);
			error!(message);
			return Err(e);
		},
	};
	let ecdsa_p256_asn1_public_pem = get_pub.as_bytes();

	// Imported PEM encoded public key as CosignVerificationKey using ECDSA_P256_ASN1_PUBLIC_PEM as
	// verification algorithm. let ecdsa_p256_asn1_public_pem =
	// std::fs::read("/keys/cosign.pub").unwrap();

	Ok(CosignVerificationKey::from_pem(ecdsa_p256_asn1_public_pem, &SigningScheme::default())?)
}

/// verify the signature of the binary file
/// # Arguments
/// * `signed_data` - The data to be signed
/// * `signature_data` - The signature of the data
/// # Returns
/// * `Result<bool, anyhow::Error>` - The result of the verification
pub fn verify(signed_data: &[u8], signature_data: &str) -> Result<bool, anyhow::Error> {
	// TODO: from github release
	let verification_key = match import_vkey() {
		Ok(key) => key,
		Err(e) => return Err(e),
	};

	//Verifying the signature of the binary file
	match verification_key
		.verify_signature(Signature::Base64Encoded(signature_data.as_bytes()), signed_data)
	{
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

#[cfg(test)]
mod test {
	use super::*;
	use base64::{engine::general_purpose, Engine as _};

	#[test]
	fn sign_test() {
		const DATA: &str = "DATA TO BE SIGNED BY COSIGN";

		/* PASSWORD MUST BE RIGHT */
		let signing_key = _import_skey("credentials/keys/dev/cosign.key", "Test123456");

		let signature = signing_key.sign(DATA.as_bytes()).unwrap();

		let encoded_sig = general_purpose::STANDARD.encode(signature);

		assert_eq!(encoded_sig, "MEYCIQCXvIjmJLmMNuMfWcFLDuseXhBgK+j68ZNJWRkmrIrZ0gIhAK7yFn9pUHOa5W1tQuU34snv4kmCMN0uTQAXwvnAz7Ld");
	}

	#[test]
	fn verify_test() {
		const DATA: &str = "DATA TO BE SIGNED BY COSIGN";
		const SIGNATURE: &str = "MEYCIQC3yrs3cZCcHVf7nNXoNgfCXCz39EHmXjkivDpUg+zc9gIhAMqeHB7Cbh7/srWAk33PzIcXKYRDHBTwwSlb26KtnTbB";

		let signature = Signature::Base64Encoded(SIGNATURE.as_bytes());
		let verification_key = import_vkey().unwrap();

		let result = matches!(verification_key.verify_signature(signature, DATA.as_bytes()), Ok(_));

		assert!(result);
	}

	#[test]
	fn verify_binary_test() {
		let binary_path = match sysinfo::get_current_pid() {
			Ok(pid) => {
				let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
				let binpath = std::path::Path::new(&path_string).read_link().unwrap();
				binpath
			},
			Err(e) => {
				tracing::error!("failed to get current pid: {}", e);
				std::path::PathBuf::new()
			},
		};
		let data = std::fs::read(binary_path).unwrap();

		let signing_key = _import_skey("credentials/keys/dev/cosign.key", "Test123456");

		let signature = signing_key.sign(&data).unwrap();
		let encoded_sig = general_purpose::STANDARD.encode(signature);

		//std::fs::write(binary_path.to_string_lossy().to_string()+".sig", encoded_sig).unwrap();

		let result = matches!(verify(&data, &encoded_sig), Ok(_));

		assert!(result);
	}
}
