use std::{
	fs::{File, OpenOptions},
	io::{Error, Read, Write},
	path::Path,
};

use tracing::info;

pub fn generate_quote(
	attestation_quote_path: Option<String>,
	enclave_file_path: Option<String>,
) -> Result<Vec<u8>, Error> {
	info!("Dumping the Quote");

	let default_enclave_path = "/quote/enclave.quote";

	let content = get_quote_content(attestation_quote_path).and_then(|result| {
		File::create(enclave_file_path.unwrap_or(String::from(default_enclave_path)))
			.and_then(|mut file| {
				file.write_all(&result).map_err(|err| {
					info!("Error writing file_4 {:?}", err);
					err
				})
			})
			.map_err(|err| {
				info!("Error Writing content");
				err
			})
			.map(|_| {
				info!("content  {:?}", result);
				result
			})
	});

	content
}

fn get_quote_content(file_path: Option<String>) -> Result<Vec<u8>, Error> {
	info!("Reading The Quote ...");
	let default_path = "/dev/attestation/quote";
	let mut content = vec![];

	File::open(file_path.unwrap_or(String::from(default_path)))
		.and_then(|mut file| {
			file.read_to_end(&mut content).map_err(|err| {
				info!("Error opening file /dev/attestation/quote {:?}", err);
				err
			})
		})
		.map(|_| {
			info!("content  {:?}", content);
			content
		})
}

/// Reads attestation type or else returns an error
fn read_attestation_type(file_path: Option<String>) -> Result<String, Error> {
	let default_path = "/dev/attestation/attestation.attestation_type";
	let mut attest_type = String::new();

	File::open(file_path.unwrap_or(String::from(default_path)))
		.and_then(|mut file| {
			file.read_to_string(&mut attest_type).map_err(|err| {
				info!("Error reading file: {:?}", err);
				err
			})
		})
		.map(|_| {
			info!("attestation type is : {}", attest_type);
			attest_type
		})
}

///  Writes user report data or else throws an Error
fn write_user_report_data(file_path: Option<String>) -> Result<(), Error> {
	let default_path = "/dev/attestation/user_report_data";
	let write_zero = [0u8; 64];
	OpenOptions::new()
		.write(true)
		.open(file_path.unwrap_or(String::from(default_path)))
		.and_then(|mut file| {
			info!("This is inside Enclave!");
			file.write_all(&write_zero).map_err(|err| {
				info!("Error writing to {} {:?}", default_path, err);
				err
			})
		})
		.map_err(|err| {
			info!("Error writing file: {:?}", err);
			err
		})
		.map(|_| ())
}

// Check if file exists with correct permissions or else returns false
fn is_user_report_data_exist(file_path: Option<String>) -> bool {
	return match file_path {
		None => Path::new("/dev/attestation/user_report_data").exists(),
		Some(_) => Path::new(file_path.unwrap().as_str()).exists(),
	}

	let mut f1 = OpenOptions::new()
		.write(true)
		.open("/dev/attestation/user_report_data")
		.unwrap(); // TODO: manage unwrap()
	info!("This is inside Enclave!");

	let mut f2 = File::open("/dev/attestation/attestation_type").unwrap(); // TODO: manage unwrap()
	let mut attest_type = String::new();
	f2.read_to_string(&mut attest_type).unwrap(); // TODO: manage unwrap()
	info!("attestation type is : {}", attest_type);

	let write_zero = [0u8; 64];
	f1.write_all(&write_zero)
		.expect("Error writing to /dev/attestation/user_report_data"); // TODO: manage expect()

	info!("Reading The Quote ...");
	let mut f3 = File::open("/dev/attestation/quote").unwrap(); // TODO: manage unwrap()
	let mut contents = vec![];
	f3.read_to_end(&mut contents).unwrap(); // TODO: manage unwrap()
										//println!("{:-#?}",contents);

	info!("Dumping the Quote");
	let mut f4 = File::create("/quote/enclave.quote").unwrap(); // TODO: manage unwrap()
	f4.write_all(&contents).unwrap(); // TODO: manage unwrap()

	contents
}
