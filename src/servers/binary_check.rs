#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use anyhow::{anyhow, Error};
use std::path::PathBuf;
use tracing::{debug, error, info};

use crate::sign::cosign;

/*  ------------------------------
		SIGNATURE
------------------------------ */
/// This function is called by the health check endpoint
pub fn self_checksig() -> Result<String, String> {
	debug!("3-4 healthcheck : checksig.");

	let binary_path: Result<PathBuf, String> = match sysinfo::get_current_pid() {
		Ok(pid) => {
			debug!("3-4-1 healthcheck : checksig : binary path detected.");
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
			match std::path::Path::new(&path_string).read_link() {
				Ok(binpath) => Ok(binpath),
				Err(e) => {
					error!("failed to read link for binary path: {}", e);
					Err("Error get binary path".to_string())
				},
			}
		},
		Err(e) => {
			error!("failed to get current pid: {}", e);
			Err("Error get binary path".to_string())
		},
	};

	let binary_path = match binary_path {
		Ok(path) => path,
		Err(msg) => return Err(msg),
	};

	let signed_data = match std::fs::read(binary_path.clone()) {
		Ok(data) => {
			debug!("3-4-2 healthcheck : checksig : binary read successfully.");
			data
		},
		Err(e) => {
			debug!("3-4-2 healthcheck : error reading binary file.");
			return Err(format!("Error reading binary file, {:?}", e));
		},
	};

	// TODO: Read from github release path
	let sigfile = binary_path.to_string_lossy().to_string() + ".sig";

	debug!("3-4-3 healthcheck : reading signature file.");
	let mut signature_data = match std::fs::read_to_string(sigfile) {
		Ok(sigdata) => {
			debug!("3-4-4 healthcheck : sig file read successfully.");
			sigdata
		},
		Err(e) => {
			debug!("3-4-4 healthcheck : fail reading sig file.");
			return Err(format!("Error reading signature file, {}", e));
		},
	};

	signature_data = signature_data.replace('\n', "");

	debug!("3-4-5 healthcheck : verification of binary signature.");
	match cosign::verify(&signed_data, &signature_data) {
		Ok(b) => match b {
			true => Ok("Successful".to_string()),
			false => Ok("Failed".to_string()),
		},
		Err(e) => Err(format!("Binary verification Error, {e}")),
	}
}

/*  ------------------------------
		CHECKSUM
------------------------------ */
/// This function is called by the health check endpoint
fn self_checksum() -> Result<String, String> {
	// Get binary address on disk
	// BUT in gramine, the binary is simply at root directory!
	let mut binary_path = match sysinfo::get_current_pid() {
		Ok(pid) => {
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";

			let binpath = match std::path::Path::new(&path_string).read_link() {
				Ok(val) => val,
				Err(err) => {
					info!("Error in binpath {:?}", err);
					PathBuf::new()
				},
			};

			binpath
		},
		Err(e) => {
			error!("failed to get current pid: {}", e);
			PathBuf::new()
		},
	};

	// Verify Ternoa checksum/signature
	let bytes = match std::fs::read(binary_path.clone()) {
		Ok(val) => val,
		Err(e) => {
			error!("failed to get current pid: {}", e);
			Vec::new()
		},
	};

	let hash = sha256::digest(bytes.as_slice());

	// TODO: Get checksum from github release
	binary_path.pop(); // remove binary name
	binary_path.push("checksum");

	let binary_hash = match std::fs::read_to_string(binary_path.clone()) {
		Ok(val) => val,
		Err(err) => {
			error!("Error readinf binary path: {err}");
			String::new()
		},
	};

	let binary_hash = binary_hash
		.strip_suffix("\r\n")
		.or(binary_hash.strip_suffix('\n'))
		.unwrap_or(&binary_hash);

	if binary_hash != hash {
		info!("Binary hash doesn't match!");
		Err(hash)
	} else {
		info!("Binary hash match : {}", hash);
		Ok(hash)
	}
}

/*  ------------------------------
	DOWNLOADER
------------------------------ */
/// This function is called by the health check endpoint
/// It downloads the binary from github release
pub fn downloader(url: &str) -> Result<String, Error> {
	let response = match reqwest::blocking::get(url) {
		Ok(resp) => resp,
		Err(e) => return Err(anyhow!("Error accessing url: {}", e)),
	};

	let content = match response.text() {
		Ok(s) => s,
		Err(e) => return Err(anyhow!("Error reading response: {}", e)),
	};

	Ok(content)
}
