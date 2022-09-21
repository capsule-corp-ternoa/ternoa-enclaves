use axum::response::IntoResponse;

use openpgp::{
	cert::prelude::*,
	crypto::{Password, SessionKey},
	parse::{stream::*, Parse},
	policy::{Policy, StandardPolicy},
	serialize::{
		stream::{Encryptor, LiteralWriter, Message, *},
		SerializeInto,
	},
	types::SymmetricAlgorithm,
};

use openpgp::types::KeyFlags;
use sequoia_openpgp as openpgp;

use blake2::{Blake2s256, Digest};
use serde::Serialize as SerderSerialize;

use std::{
	fs::create_dir_all,
	io::{Read, Write},
	sync::Arc,
};

use crate::{
	ipfs::{TernoaIpfsApi, IPFS_API_URL, IPFS_GATEWAY_URL},
	zipdir::add_dir_zip,
};

const KEY_DIR_PATH: &str = "./credentials/keys/";

fn random_string<S: AsRef<str>>(length: usize, charset: S) -> String {
	let charset_str = charset.as_ref();

	if charset_str.is_empty() {
		return "Provided charset is empty! It should contain at least one character".to_string();
	}

	let chars: Vec<char> = charset_str.chars().collect();
	let mut result = String::with_capacity(length);

	unsafe {
		for _ in 0..length {
			result.push(*chars.get_unchecked(fastrand::usize(0..chars.len())));
		}
	}

	result
}

fn random_hash() -> [u8; 32] {
	let character_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let rs = random_string(20, character_set);

	let mut hasher = Blake2s256::new();
	hasher.update(rs);
	let res: [u8; 32] = hasher.finalize().into();
	res
}

pub async fn generate_key() -> impl IntoResponse {
	let character_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
	let password = random_string(20, character_set);

	let p = &StandardPolicy::new();
	let (ecc, _) = CertBuilder::general_purpose(None, Some("alice@ternoa.com"))
		.set_cipher_suite(CipherSuite::Cv25519)
		.add_subkey(
			KeyFlags::empty().set_storage_encryption().set_transport_encryption(),
			std::time::Duration::new(365 * 24 * 60 * 60, 0),
			None,
		)
		.set_password(Some(password.clone().into()))
		.generate()
		.unwrap();

	// let mut buf = Vec::new();
	// ecc.as_tsk()
	//     .set_filter(|k| k.fingerprint() != ecc.fingerprint())
	//     .emit_secret_key_stubs(true)
	//     .serialize(&mut buf)
	//     .unwrap();

	let public_key = String::from_utf8(ecc.armored().to_vec().unwrap()).unwrap();
	let private_key = String::from_utf8(ecc.as_tsk().armored().to_vec().unwrap()).unwrap();

	create_dir_all(KEY_DIR_PATH).unwrap();
	/*
	println!("Current Path is {}\n", std::env::current_dir().unwrap().display());
	let test_paths = std::fs::read_dir("./").unwrap();
	for tp in test_paths {
		println!("Name: {}", tp.unwrap().path().display())
	}
	println!("\n\n");

	if let Ok(entries) = std::fs::read_dir("/credentials") {
		for entry in entries {
			if let Ok(entry) = entry {
				// Here, `entry` is a `DirEntry`.
				if let Ok(metadata) = entry.metadata() {
					// Now let's show our entry's permissions!
					println!("{:?}: {:?}", entry.path(), metadata.permissions());
				} else {
					println!("Couldn't get metadata for {:?}", entry.path());
				}
			}
		}
	}
	*/

	// Write Password to file
	let mut passwordfile = std::fs::File::create(KEY_DIR_PATH.to_owned() + "password.txt")
		.expect("create password file, failed");
	//write!(passwordfile, "{}", password).unwrap();
	passwordfile
		.write_all(password.clone().as_bytes())
		.expect("write private.txt failed");

	// Write Private Key to file
	let mut privatefile = std::fs::File::create(KEY_DIR_PATH.to_owned() + "private.txt")
		.expect("create private-key file, failed");
	//write!(privatefile, "{}", private_key).unwrap();
	privatefile.write_all(private_key.as_bytes()).expect("write private.txt failed");

	// Write Public Key to file
	let mut publicfile = std::fs::File::create(KEY_DIR_PATH.to_owned() + "public.txt")
		.expect("create public-key file, failed");
	//write!(publicfile, "{}", public_key).unwrap();
	publicfile.write_all(public_key.as_bytes()).expect("write public.txt failed");

	println!("Credentials has been written to file");

	let full_path = KEY_DIR_PATH.to_string() + "public.txt";
	let path = std::path::Path::new(&full_path);

	// Upload to IPFS
	let ternoa_ipfs = TernoaIpfsApi::new(&IPFS_API_URL.to_string(), &IPFS_GATEWAY_URL.to_string());
	let cid = ternoa_ipfs.add_file(path).await;

	// IPFS url
	let mut public_urlfile =
		std::fs::File::create(KEY_DIR_PATH.to_owned() + "publicUrl.txt").expect("create failed");
	public_urlfile
		.write_all((IPFS_GATEWAY_URL.to_owned() + &cid).as_bytes())
		.expect("write publicUrl.txt failed");

	// Create ZIP file
	let zipfile = KEY_DIR_PATH.to_owned() + "keys.zip";
	add_dir_zip(KEY_DIR_PATH, zipfile.as_str());
}

#[derive(SerderSerialize)]
struct PublicUrl {
	status: u16,
	file: String,
}

#[derive(SerderSerialize)]
struct JsonPublicKey {
	status: u16,
	publickey: Vec<u8>,
}

pub async fn get_public_key() -> impl IntoResponse {
	let file_path = KEY_DIR_PATH.to_owned() + "public.txt";
	let file = std::fs::File::open(file_path).unwrap();

	let cert = Cert::from_reader(file).unwrap();
	let buf = cert.armored().export_to_vec().unwrap();

	axum::Json(JsonPublicKey { status: 200, publickey: buf })
}

pub async fn get_public_key_url() -> impl IntoResponse {
	let file_path = KEY_DIR_PATH.to_owned() + "publicUrl.txt";
	let mut file = std::fs::File::open(file_path).unwrap();
	let mut contents = String::new();
	file.read_to_string(&mut contents).unwrap();

	axum::Json(PublicUrl { status: 200, file: contents })
}

pub async fn cert_from_privatekey() -> Cert {
	let key_file_path = KEY_DIR_PATH.to_owned() + "private.txt";
	let pass_file_path = KEY_DIR_PATH.to_owned() + "password.txt";

	let key_file = std::fs::File::open(key_file_path).unwrap();
	let mut pass_file = std::fs::File::open(pass_file_path).unwrap();

	let mut pass_contents = Vec::<u8>::new();

	pass_file.read_to_end(&mut pass_contents).unwrap();

	//let cert = Cert::from_str(String::from_utf8(key_contents).unwrap().as_str()).unwrap();
	let cert = Cert::from_reader(key_file).unwrap();
	let password = Password::from(pass_contents);
	let pk = cert
		.primary_key()
		.key()
		.clone()
		.parts_into_secret()
		.unwrap()
		.decrypt_secret(&password)
		.unwrap();
	//cert.armored().serialize(&mut output).unwrap();
	let (cert, _) = cert.insert_packets_merge(pk, |_old, new| Ok(new)).unwrap();

	cert
}

/* ******** ASYNCHRONOUS ENCRYPTION/DECRYPTION ******** */

/// Generates an encryption-capable key.
fn generate() -> openpgp::Result<openpgp::Cert> {
	let (cert, _revocation) = CertBuilder::new()
		.add_userid("alice@ternoa.com")
		.add_transport_encryption_subkey()
		.add_signing_subkey()
		.generate()
		.unwrap();

	// Save the revocation certificate somewhere.

	Ok(cert)
}

/// Encrypts the given message.
pub fn encrypt(sink: &mut (dyn Write + Send + Sync), plaintext: &str, recipient: &openpgp::Cert) {
	let p = &StandardPolicy::new();
	let recipients = recipient
		.keys()
		.with_policy(p, None)
		.supported()
		.alive()
		.revoked(false)
		.for_transport_encryption();

	// Start streaming an OpenPGP message.
	let message = Message::new(sink);

	// We want to encrypt a literal data packet.
	let message = Encryptor::for_recipients(message, recipients).build().unwrap();

	// Emit a literal data packet.
	let mut message = LiteralWriter::new(message).build().unwrap();

	// Encrypt the data.
	message.write_all(plaintext.as_bytes()).unwrap();

	// Finalize the OpenPGP message to make sure that all data is
	// written.
	message.finalize().unwrap();
}

/// Decrypts the given message.
pub fn decrypt(sink: &mut dyn Write, ciphertext: &[u8], recipient: &openpgp::Cert) {
	// Make a helper that that feeds the recipient's secret key to the
	// decryptor.
	let p = &StandardPolicy::new();
	let helper = CHelper { secret: recipient, policy: p };

	// Now, create a decryptor with a helper using the given Certs.
	let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
		.unwrap()
		.with_policy(p, None, helper)
		.unwrap();

	// Decrypt the data.
	Arc::new(std::io::copy(&mut decryptor, sink));
}

struct CHelper<'a> {
	secret: &'a openpgp::Cert,
	policy: &'a dyn Policy,
}

impl<'a> VerificationHelper for CHelper<'a> {
	fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
		// Return public keys for signature verification here.
		Ok(Vec::new())
	}

	fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
		// Implement your signature verification policy here.
		Ok(())
	}
}

impl<'a> DecryptionHelper for CHelper<'a> {
	fn decrypt<D>(
		&mut self,
		pkesks: &[openpgp::packet::PKESK],
		_skesks: &[openpgp::packet::SKESK],
		sym_algo: Option<SymmetricAlgorithm>,
		mut decrypt: D,
	) -> openpgp::Result<Option<openpgp::Fingerprint>>
	where
		D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
	{
		let key = self
			.secret
			.keys()
			.unencrypted_secret()
			.with_policy(self.policy, None)
			.for_transport_encryption()
			.next()
			.unwrap()
			.key()
			.clone();

		// The secret key is not encrypted.
		let mut pair = key.into_keypair().unwrap();

		pkesks[0]
			.decrypt(&mut pair, sym_algo)
			.map(|(algo, session_key)| decrypt(algo, &session_key));

		// XXX: In production code, return the Fingerprint of the
		// recipient's Cert here
		Ok(None)
	}
}

/* ******** SIGNATURE ******** */
struct SHelper<'a> {
	cert: &'a openpgp::Cert,
}

impl<'a> VerificationHelper for SHelper<'a> {
	fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
		// Return public keys for signature verification here.
		Ok(vec![self.cert.clone()])
	}

	fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
		// In this function, we implement our signature verification
		// policy.

		let mut good = false;
		for (i, layer) in structure.into_iter().enumerate() {
			match (i, layer) {
				// First, we are interested in signatures over the
				// data, i.e. level 0 signatures.
				(0, MessageLayer::SignatureGroup { results }) => {
					// Finally, given a VerificationResult, which only says
					// whether the signature checks out mathematically, we apply
					// our policy.
					match results.into_iter().next() {
						Some(Ok(_)) => good = true,
						Some(Err(e)) => return Err(openpgp::Error::from(e).into()),
						None => return Err(anyhow::anyhow!("No signature")),
					}
				},
				_ => return Err(anyhow::anyhow!("Unexpected message structure")),
			}
		}

		if good {
			Ok(()) // Good signature.
		} else {
			Err(anyhow::anyhow!("Signature verification failed"))
		}
	}
}

/// Signs the given message.
fn sign(sink: &mut (dyn Write + Send + Sync), plaintext: &str, tsk: &openpgp::Cert) {
	let p = &StandardPolicy::new();
	// Get the keypair to do the signing from the Cert.
	let keypair = tsk
		.keys()
		.unencrypted_secret()
		.with_policy(p, None)
		.supported()
		.alive()
		.revoked(false)
		.for_signing()
		.next()
		.unwrap()
		.key()
		.clone()
		.into_keypair()
		.unwrap();

	// Start streaming an OpenPGP message.
	let message = Message::new(sink);

	// We want to sign a literal data packet.
	let signer = Signer::new(message, keypair).build().unwrap();

	// Emit a literal data packet.
	let mut literal_writer = LiteralWriter::new(signer).build().unwrap();

	// Sign the data.
	literal_writer.write_all(plaintext.as_bytes()).unwrap();

	// Finalize the OpenPGP message to make sure that all data is
	// written.
	literal_writer.finalize().unwrap();
}

/// Verifies the given message.
fn verify(sink: &mut dyn Write, signed_message: &[u8], sender: &openpgp::Cert) {
	let p = &StandardPolicy::new();
	// Make a helper that that feeds the sender's public key to the
	// verifier.
	let helper = SHelper { cert: sender };

	// Now, create a verifier with a helper using the given Certs.
	let mut verifier = VerifierBuilder::from_bytes(signed_message)
		.unwrap()
		.with_policy(p, None, helper)
		.unwrap();

	// Verify the data.
	std::io::copy(&mut verifier, sink).unwrap();
}

/* ------------  TESTS  ----------- */

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_generate_keys() {
		generate_key().await;
	}

	#[tokio::test]
	async fn test_get_keys() {
		get_public_key().await;
	}

	#[tokio::test]
	async fn test_get_url() {
		get_public_key_url().await;
	}

	#[tokio::test]
	async fn test_import_priate_key() {
		let cert = cert_from_privatekey().await;

		println!("Cert = {}", String::from_utf8(cert.armored().to_vec().unwrap()).unwrap())
	}

	#[tokio::test]
	async fn test_enc_dec() {
		const MESSAGE: &str = "дружба";
		let p = &StandardPolicy::new();

		// Generate a key.
		let key = generate().unwrap();

		// Encrypt the message.
		let mut ciphertext = Vec::new();
		encrypt(&mut ciphertext, MESSAGE, &key);

		// Decrypt the message.
		let mut plaintext = Vec::new();
		decrypt(&mut plaintext, &ciphertext, &key);

		assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
	}

	#[tokio::test]
	async fn test_sign_verify() {
		const MESSAGE: &str = "дружба";
		println!("Message = {}", MESSAGE);

		// Generate a key.
		let key = generate().unwrap();
		println!("Key = {}", key);

		// Sign the message.
		let mut signed_message = Vec::new();
		sign(&mut signed_message, MESSAGE, &key);
		println!("Signed Message = {:-?}", signed_message);

		// Verify the message.
		let mut plaintext = Vec::new();
		verify(&mut plaintext, &signed_message, &key);
		println!("Verified Message = {}", String::from_utf8(plaintext.clone()).unwrap());

		assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
	}
}
