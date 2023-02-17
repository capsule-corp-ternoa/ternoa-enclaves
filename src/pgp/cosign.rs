use anyhow::Result;

use sigstore::crypto::{
	signing_key::{ecdsa::ECDSAKeys, SigStoreKeyPair},
	CosignVerificationKey, SigStoreSigner, Signature, SigningScheme,
};

use crate::servers::http_server::downloader;

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
	let ecdsa_signer_pair = ecdsa_key_pair.to_sigstore_signer().unwrap();

	ecdsa_signer_pair
}

fn import_vkey() -> CosignVerificationKey {
	// Imported PEM encoded public key as CosignVerificationKey using ECDSA_P256_ASN1_PUBLIC_PEM as verification algorithm.
	// Production
	//let ecdsa_p256_asn1_public_pem = std::fs::read("keys/cosign.pub").unwrap();
	// Test
	let url = "https://gist.githubusercontent.com/zorvan/46b26ff51b27590683ddaf70c0ea9dac/raw/2b437edaa808b79f2e7768cde9085150b2f10a32/cosign.pub";
	let get_pub = downloader(url).unwrap();
	let ecdsa_p256_asn1_public_pem = get_pub.as_bytes();

	//let ecdsa_p256_asn1_public_pem = std::fs::read("./bin/cosign.pub").unwrap();
	let verification_key =
		CosignVerificationKey::from_pem(ecdsa_p256_asn1_public_pem, &SigningScheme::default())
			.unwrap();

	verification_key
}

pub fn verify(signed_data: &[u8], signature_data: &str) -> Result<bool, anyhow::Error> {
	// TODO: from github release
	let verification_key = import_vkey();

	//Verifying the signature of the binary file
	match verification_key
		.verify_signature(Signature::Base64Encoded(signature_data.as_bytes()), &signed_data)
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

		/* PASSWORD MUST BE RIGHT*/
		let signing_key = _import_skey("credentials/keys/cosign.key", "Test123456");

		let signature = signing_key.sign(DATA.as_bytes()).unwrap();

		let encoded_sig = general_purpose::STANDARD.encode(&signature);

		assert_eq!(encoded_sig, "MEYCIQCXvIjmJLmMNuMfWcFLDuseXhBgK+j68ZNJWRkmrIrZ0gIhAK7yFn9pUHOa5W1tQuU34snv4kmCMN0uTQAXwvnAz7Ld");
	}

	#[test]
	fn verify_test() {
		const DATA: &str = "DATA TO BE SIGNED BY COSIGN";
		const SIGNATURE: &str = "MEYCIQC3yrs3cZCcHVf7nNXoNgfCXCz39EHmXjkivDpUg+zc9gIhAMqeHB7Cbh7/srWAk33PzIcXKYRDHBTwwSlb26KtnTbB";

		let signature = Signature::Base64Encoded(SIGNATURE.as_bytes());
		let verification_key = import_vkey();

		let result = match verification_key.verify_signature(signature, DATA.as_bytes()) {
			Ok(_) => true,
			_ => false,
		};

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
		let data = std::fs::read(binary_path.clone()).unwrap();

		let signing_key = _import_skey("credentials/keys/cosign.key", "Test123456");

		let signature = signing_key.sign(&data).unwrap();
		let encoded_sig = general_purpose::STANDARD.encode(signature);

		//std::fs::write(binary_path.to_string_lossy().to_string()+".sig", encoded_sig).unwrap();

		let result = match verify(&data, &encoded_sig) {
			Ok(_) => true,
			_ => false,
		};

		assert!(result);
	}
}
