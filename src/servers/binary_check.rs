#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use std::path::PathBuf;
use tracing::{debug, error, info};

use crate::sign::cosign;

/*  ------------------------------
		SIGNATURE
------------------------------ */
/// This function is called by the health check endpoint
pub fn self_checksig() -> Result<String, String> {
	debug!("BINARY-CHECK : checksig.");

	let binary_path: Result<PathBuf, String> = match sysinfo::get_current_pid() {
		Ok(pid) => {
			debug!("BINARY-CHECK : checksig : binary path detected.");
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
			match std::path::Path::new(&path_string).read_link() {
				Ok(binpath) => Ok(binpath),
				Err(err) => {
					error!("failed to read link for binary path: {}", err);
					Err("Error get binary path".to_string())
				},
			}
		},
		Err(err) => {
			error!("failed to get current pid: {}", err);
			Err("Error get binary path".to_string())
		},
	};

	let binary_path = match binary_path {
		Ok(path) => path,
		Err(msg) => return Err(msg),
	};

	let signed_data = match std::fs::read(binary_path.clone()) {
		Ok(data) => {
			debug!("BINARY-CHECK : checksig : binary read successfully.");
			data
		},
		Err(err) => {
			debug!("BINARY-CHECK : error reading binary file.");
			return Err(format!("Error reading binary file, {err:?}"));
		},
	};

	// Read from github release path
	let sigfile = binary_path.to_string_lossy().to_string() + ".sig";

	debug!("BINARY-CHECK : reading signature file.");
	let mut signature_data = match std::fs::read_to_string(sigfile) {
		Ok(sigdata) => {
			debug!("BINARY-CHECK : sig file read successfully.");
			sigdata
		},
		Err(err) => {
			debug!("BINARY-CHECK : fail reading sig file.");
			return Err(format!("Error reading signature file, {}", err));
		},
	};

	signature_data = signature_data.replace('\n', "");

	debug!("BINARY-CHECK : verification of binary signature.");
	match cosign::verify(&signed_data, &signature_data) {
		Ok(b) => match b {
			true => Ok("Successful".to_string()),
			false => Ok("Failed".to_string()),
		},
		Err(err) => Err(format!("Binary verification Error, {err}")),
	}
}
