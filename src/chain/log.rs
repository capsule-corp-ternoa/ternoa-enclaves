#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::upper_case_acronyms)]

use std::{
	collections::BTreeMap,
	error::Error,
	fs::{File, OpenOptions},
	io::{Read, Seek, SeekFrom, Write},
};

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use super::verify::RequesterType;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NFTType {
	SECRET,
	CAPSULE,
	NONE,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum LogType {
	STORE,
	VIEW,
	BURN,
	NONE,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LogAccount {
	pub address: String,
	pub role: RequesterType,
}

impl LogAccount {
	pub fn new(address: String, role: RequesterType) -> LogAccount {
		LogAccount { address, role }
	}
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LogStruct {
	pub date: String,
	pub block: u32,
	pub account: LogAccount,
	pub event: LogType,
}

impl LogStruct {
	pub fn new(block: u32, account: LogAccount, event: LogType) -> LogStruct {
		let current_date: chrono::DateTime<chrono::offset::Utc> =
			std::time::SystemTime::now().into();
		let date = current_date.format("%Y-%m-%d %H:%M:%S").to_string();
		LogStruct { date, block, account, event }
	}
}

type Index = u32;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LogFile {
	pub secret_nft: BTreeMap<Index, LogStruct>,
	pub capsule: BTreeMap<Index, LogStruct>,
}

impl LogFile {
	/// Create a new LogFile
	pub fn new() -> LogFile {
		LogFile { secret_nft: BTreeMap::new(), capsule: BTreeMap::new() }
	}

	/// Insert a new log in the log file
	pub fn insert_new_nft_log(&mut self, log: LogStruct) {
		let index = self.secret_nft.len() as u32;
		self.secret_nft.insert(index, log);
	}

	/// Insert a new log in the log file
	pub fn insert_new_capsule_log(&mut self, log: LogStruct) {
		let index = self.capsule.len() as u32;
		self.capsule.insert(index, log);
	}
}

/// update log file view
/// # Arguments
/// * `file_path` - path of the log file
/// * `requester_address` - address of the requester
/// * `requester_type` - type of the requester
/// * `log_type` - type of the log
/// * `nft_type` - type of the nft
pub fn update_log_file_view(
	block_number: u32,
	file_path: String,
	requester_address: String,
	requester_type: RequesterType,
	log_type: LogType,
	nft_type: &str,
) -> bool {
	if let Err(err) =
		update_view(block_number, file_path, requester_address, requester_type, log_type, nft_type)
	{
		error!("Unable to update log file view: {}", err);
		return false;
	}

	true
}

/// update_view
fn update_view(
	block_number: u32,
	file_path: String,
	requester_address: String,
	requester_type: RequesterType,
	log_type: LogType,
	nft_type: &str,
) -> Result<(), Box<dyn Error>> {
	debug!("4-7 update log file view");

	let mut log_file = OpenOptions::new().read(true).write(true).append(false).open(file_path)?;

	let mut old_logs = String::new();
	log_file.read_to_string(&mut old_logs)?;

	log_file.seek(SeekFrom::Start(0))?;

	let mut log_file_struct: LogFile = serde_json::from_str(&old_logs)?;

	let log_account = LogAccount::new(requester_address, requester_type);
	let new_log = LogStruct::new(block_number, log_account, log_type);

	if nft_type == "capsule" {
		log_file_struct.insert_new_capsule_log(new_log);
	} else if nft_type == "secret-nft" {
		log_file_struct.insert_new_nft_log(new_log);
	}

	let log_buf = serde_json::to_vec(&log_file_struct)?;
	log_file.write_all(&log_buf)?;

	Ok(())
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use tokio_test::assert_err;

	use super::*;

	#[tokio::test]
	async fn read_log_test() {
		let store_body = r#"
        {
            "secret_nft": {
                "0": {
                    "date": "2023-02-21 16:34:57",
                    "account": {
                        "address": "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5",
                        "role": "OWNER"
                    },
                    "event": "STORE"
                },
        
                "1": {
                    "date": "2023-02-21 16:54:00",
                    "account": {
                        "address": "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5",
                        "role": "DELEGATEE"
                    },
                    "event": "VIEW"
                }
            },
        
            "capsule": {
                "0": {
                    "date": "2024-03-22 17:35:58",
                    "account": {
                        "address": "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5",
                        "role": "OWNER"
                    },
                    "event": "STORE"
                },
        
                "1": {
                    "date": "2024-03-22 17:45:10",
                    "account": {
                        "address": "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5",
                        "role": "DELEGATEE"
                    },
                    "event": "VIEW"
                }
            }
        }"#;

		let mut log_file: LogFile =
			serde_json::from_str(store_body).expect("error deserailizing json body");

		let nft_second_account_role = match log_file.secret_nft.get(&1) {
			Some(event) => event.account.role,
			None => panic!("There is no second account!"),
		};

		assert_eq!(nft_second_account_role, RequesterType::DELEGATEE);

		let new_log_body = r#"
        {
            "date": "2023-03-23 16:50:25",
            "account": {
                "address": "5TQAxH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa7",
                "role": "RENTEE"
            },
            "event": "VIEW"
        }"#;

		let new_log: LogStruct =
			serde_json::from_str(new_log_body).expect("error deserailizing json body");
		log_file.insert_new_capsule_log(new_log);

		let correct_log = r#"
        {
            "secret_nft": {
                "0": {
                    "date": "2023-02-21 16:34:57",
                    "account": {
                        "address": "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5",
                        "role": "OWNER"
                    },
                    "event": "STORE"
                },
        
                "1": {
                    "date": "2023-02-21 16:54:00",
                    "account": {
                        "address": "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5",
                        "role": "DELEGATEE"
                    },
                    "event": "VIEW"
                }
            },
        
            "capsule": {
                "0":  {
                    "date": "2024-03-22 17:35:58",
                    "account":  {
                        "address": "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5",
                        "role": "OWNER"
                    },
                    "event": "STORE"
                },

                "1": {
                    "date": "2024-03-22 17:45:10",
                    "account":  {
                        "address": "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5",
                        "role": "DELEGATEE"
                    },
                    "event": "VIEW"
                },

                "2": {
                    "date": "2023-03-23 16:50:25",
                    "account": {
                        "address": "5TQAxH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa7",
                        "role": "RENTEE"
                    },
                    "event": "VIEW"
                }
            }
        }
        "#;

		assert_eq!(
			log_file,
			serde_json::from_str(correct_log).expect("error deserializing json body")
		);
	}

	#[tokio::test]
	async fn file_log_test() {
		let file_name = "./test/test.log".to_string();
		// Simulating the Store keyshare process
		let mut file = File::create(file_name.clone()).unwrap();
		let owner = "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5".to_string();

		let mut log_file_struct = LogFile::new();
		let log_account = LogAccount::new(owner, RequesterType::OWNER);
		let new_log = LogStruct::new(100000, log_account, LogType::STORE);
		log_file_struct.insert_new_nft_log(new_log);

		let log_buf = serde_json::to_vec(&log_file_struct).unwrap();

		file.write_all(&log_buf).unwrap();
		std::mem::drop(file);

		// Simulating Retrive keyshare
		let requester_address = "5TQAxH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa7".to_string();
		update_log_file_view(
			100000,
			file_name.clone(),
			requester_address,
			RequesterType::DELEGATEE,
			LogType::VIEW,
			"secret-nft",
		);

		// Simulating convert to capsule
		let requester_address = "5CDGXH8Q9DzD3TnATTG6qm6f4yR1kbECBGUmh2XbEBQ8Jfa5".to_string();
		update_log_file_view(
			1000000,
			file_name.clone(),
			requester_address,
			RequesterType::OWNER,
			LogType::STORE,
			"capsule",
		);

		// Simulate viewing the log
		let mut file = File::open(file_name.clone()).unwrap();
		let mut content = String::new();
		file.read_to_string(&mut content).unwrap();

		println!("{content}");

		// Clean up
		std::fs::remove_file(file_name).unwrap();
	}
}