use anyhow::Result;

use anyhow::{anyhow, Error};
use sigstore::crypto::{
	signing_key::{ecdsa::ECDSAKeys, SigStoreKeyPair},
	CosignVerificationKey, SigStoreSigner, Signature, SigningScheme,
};
use tracing::error;

use crate::chain::constants::GITHUB_SIGN_PUBLIC_KEY;

/* ------------------------------
		DOWNLOADER
------------------------------ */
/// This function is called by the health check endpoint
/// It downloads the signature from github release
pub fn downloader(url: &str) -> Result<String, Error> {
	let response = match reqwest::blocking::get(url) {
		Ok(resp) => resp,
		Err(err) => return Err(anyhow!("Error accessing url: {}", err)),
	};

	let content = match response.text() {
		Ok(s) => s,
		Err(err) => return Err(anyhow!("Error reading response: {}", err)),
	};

	Ok(content)
}

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
	let url = GITHUB_SIGN_PUBLIC_KEY;
	tracing::debug!("COSIGN : Download cosign public-key from github.");

	let get_pub = match downloader(url) {
		Ok(data) => data,
		Err(err) => {
			let message =
				format!("COSIGN : error retrieving public key from ternoa github {}", err);
			error!(message);
			return Err(err);
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
	// TODO [release deployment] : from github release
	let verification_key = match import_vkey() {
		Ok(key) => key,
		Err(err) => return Err(err),
	};

	//Verifying the signature of the binary file
	match verification_key
		.verify_signature(Signature::Base64Encoded(signature_data.as_bytes()), signed_data)
	{
		Ok(_) => {
			tracing::info!("COSIGN : Binary file Verification Succeeded.");
			Ok(true)
		},

		Err(err) => {
			tracing::error!("COSIGN : Binary file signature verification failed, {}", err);
			Ok(false)
		},
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use base64::Engine;

	#[test]
	fn verify_test() {
		const DATA: &str = "DATA TO BE SIGNED BY COSIGN";
		const SIGNATURE: &str = "MEYCIQC3yrs3cZCcHVf7nNXoNgfCXCz39EHmXjkivDpUg+zc9gIhAMqeHB7Cbh7/srWAk33PzIcXKYRDHBTwwSlb26KtnTbB";

		let signature = Signature::Base64Encoded(SIGNATURE.as_bytes());
		let verification_key = import_vkey().unwrap();

		let result = verification_key.verify_signature(signature, DATA.as_bytes()).is_ok();

		assert!(result);
	}

	#[cfg(any(feature = "dev1-net", feature = "dev0-net"))]
	#[test]
	fn sign_test() {
		const DATA: &str = "DATA TO BE SIGNED BY COSIGN";

		/* PASSWORD MUST BE RIGHT */
		let signing_key = _import_skey("credentials/keys/dev/cosign.key", "Test123456");

		let signature = signing_key.sign(DATA.as_bytes()).unwrap();

		let encoded_sig = base64::engine::general_purpose::STANDARD.encode(signature);

		assert_eq!(encoded_sig, "MEYCIQCXvIjmJLmMNuMfWcFLDuseXhBgK+j68ZNJWRkmrIrZ0gIhAK7yFn9pUHOa5W1tQuU34snv4kmCMN0uTQAXwvnAz7Ld");
	}

	#[cfg(any(feature = "dev1-net", feature = "dev0-net"))]
	#[test]
	fn verify_binary_test() {
		let binary_path = match sysinfo::get_current_pid() {
			Ok(pid) => {
				let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
				let binpath = std::path::Path::new(&path_string).read_link().unwrap();
				binpath
			},
			Err(err) => {
				tracing::error!("COSIGN : failed to get current pid: {}", err);
				std::path::PathBuf::new()
			},
		};
		let data = std::fs::read(binary_path).unwrap();

		let signing_key = _import_skey("credentials/keys/dev/cosign.key", "Test123456");

		let signature = signing_key.sign(&data).unwrap();
		let encoded_sig = base64::engine::general_purpose::STANDARD.encode(signature);

		//std::fs::write(binary_path.to_string_lossy().to_string()+".sig", encoded_sig).unwrap();

		let result = verify(&data, &encoded_sig).is_ok();

		assert!(result);
	}
}
