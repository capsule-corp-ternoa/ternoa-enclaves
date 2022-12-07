use std::{
	fs::File,
	io::{Read, Write},
};
use tracing::info;

pub fn generate_quote() -> Vec<u8> {
	if !std::path::Path::new("/dev/attestation/user_report_data").exists() {
		info!("This is NOT inside an Enclave!");
		return Vec::new();
	}

	let mut f1 = File::open("/dev/attestation/user_report_data").unwrap();
	info!("This is inside Enclave!");

	let mut f2 = File::open("/dev/attestation/attestation_type").unwrap();
	let mut attest_type = String::new();
	f2.read_to_string(&mut attest_type).unwrap();
	info!("attestation type is : {}", attest_type);

	let write_zero = [0u8; 64];
	f1.write_all(&write_zero).unwrap();

	info!("Reading The Quote ...");
	let mut f3 = File::open("/dev/attestation/quote").unwrap();
	let mut contents = vec![];
	f3.read_to_end(&mut contents).unwrap();
	//println!("{:-#?}",contents);

	info!("Writing the Quote");
	let mut f4 = File::create("/quote/enclave.quote").unwrap();
	f4.write_all(&contents).unwrap();

	return contents;
}
