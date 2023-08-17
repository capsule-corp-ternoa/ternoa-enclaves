#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

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

use std::{io::Write, sync::Arc};

pub fn pgp_generate_key() {
	let password = "123456";

	let _p = &StandardPolicy::new();
	let (ecc, _) = CertBuilder::general_purpose(None, Some("alice@ternoa.com"))
		.set_cipher_suite(CipherSuite::Cv25519)
		.add_subkey(
			KeyFlags::empty().set_storage_encryption().set_transport_encryption(),
			std::time::Duration::new(365 * 24 * 60 * 60, 0),
			None,
		)
		.set_password(Some((*password).into()))
		.generate()
		.unwrap();

	// let mut buf = Vec::new();
	// ecc.as_tsk()
	//     .set_filter(|k| k.fingerprint() != ecc.fingerprint())
	//     .emit_secret_key_stubs(true)
	//     .serialize(&mut buf)
	//     .unwrap();

	let _public_key = String::from_utf8(ecc.armored().to_vec().unwrap()).unwrap();
	let _private_key = String::from_utf8(ecc.as_tsk().armored().to_vec().unwrap()).unwrap();
}

/// Encrypts the given message.
pub fn pgp_get_public_key(key_stream: std::fs::File) -> Vec<u8> {
	let cert = Cert::from_reader(key_stream).unwrap();
	let buf = cert.armored().export_to_vec().unwrap();
	buf
}

/// Decrypts the given message.
pub fn pgp_cert_from_privatekey(key_stream: std::fs::File) -> Cert {
	let password = "123456";

	//let cert = Cert::from_str(String::from_utf8(key_contents).unwrap().as_str()).unwrap();
	let cert = Cert::from_reader(key_stream).unwrap();
	let password = Password::from(password);
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
fn pgp_generate() -> Cert {
	let (cert, _revocation) = CertBuilder::new()
		.add_userid("alice@ternoa.com")
		.add_transport_encryption_subkey()
		.add_signing_subkey()
		.generate()
		.unwrap();

	// Save the revocation certificate somewhere.

	cert
}

/// Encrypts the given message.
pub fn pgp_encrypt(
	sink: &mut (dyn Write + Send + Sync),
	plaintext: &str,
	recipient: &openpgp::Cert,
) {
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

	// Encrypt a literal data packet.
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
pub fn pgp_decrypt(sink: &mut dyn Write, ciphertext: &[u8], recipient: &openpgp::Cert) {
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

/// A helper that provides the recipient's secret key.
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

/// A helper that provides the recipient's secret key.
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
						Some(Err(err)) => return Err(openpgp::Error::from(err).into()),
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

fn pgp_sign(sink: &mut (dyn Write + Send + Sync), plaintext: &str, tsk: &openpgp::Cert) {
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

fn pgp_verify(sink: &mut dyn Write, signed_message: &[u8], sender: &openpgp::Cert) {
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

	#[test]
	fn test_generate_keys() {
		pgp_generate_key();
	}
	/* Define test files.

	#[test]
	fn test_get_keys() {
		let f = std::fs::File::open("public.key").expect("can not open test file");
		_get_public_key(f);
	}

	#[test]
	fn test_import_private_key() {
		let f = std::fs::File::open("private.key").expect("can not open test file");
		let cert = _cert_from_privatekey(f);

		println!("Cert = {}", String::from_utf8(cert.armored().to_vec().unwrap()).unwrap())
	}
	*/
	#[test]
	fn test_enc_dec() {
		const MESSAGE: &str = "дружба";
		let _p = &StandardPolicy::new();

		// Generate a key.

		let key = pgp_generate();

		// Encrypt the message.
		let mut ciphertext = Vec::new();
		pgp_encrypt(&mut ciphertext, MESSAGE, &key);

		// Decrypt the message.
		let mut plaintext = Vec::new();
		pgp_decrypt(&mut plaintext, &ciphertext, &key);


		assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
	}

	#[test]
	fn test_sign_verify() {
		const MESSAGE: &str = "дружба";
		println!("Message = {MESSAGE}");

		// Generate a key.

		let key = pgp_generate();
		println!("Key = {key}");

		// Sign the message.
		let mut signed_message = Vec::new();
		pgp_sign(&mut signed_message, MESSAGE, &key);
		println!("Signed Message = {signed_message:-?}");

		// Verify the message.
		let mut plaintext = Vec::new();
		pgp_verify(&mut plaintext, &signed_message, &key);

		println!("Verified Message = {}", String::from_utf8(plaintext.clone()).unwrap());

		assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
	}
}
