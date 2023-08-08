use std::collections::BTreeMap;

use anyhow::anyhow;
use tracing::{debug, error, warn};

pub fn query_nftid_file(dir_path: String, nft_id: u32) -> Result<u32, anyhow::Error> {
	let dir_iterator = match std::fs::read_dir(dir_path) {
		Ok(it) => it,
		Err(e) => {
			// It's better to have a error response
			let message = format!("QUERY NFTID FILE : error reading seales directory {:?}", e);
			error!(message);
			return Err(anyhow!(message));
		},
	};

	for direntry in dir_iterator {
		let entry = match direntry {
			Ok(entry) => entry,
			// It's better to report Internal Error
			Err(e) => {
				error!("QUERY NFTID FILE : error reading directory entry {:?}", e);
				continue;
			},
		};

		let path = entry.path();

		let name_parts: Vec<&str> = match path.file_stem().and_then(std::ffi::OsStr::to_str) {
			Some(name) => name.split('_').collect(),
			None => continue,
		};

		let file_ext = match path.extension().and_then(std::ffi::OsStr::to_str) {
			Some(ext) => ext,
			None => continue,
		};

		if file_ext == "keyshare"
			&& name_parts.len() == 3
			&& (name_parts[0] == "nft" || name_parts[0] == "capsule")
			&& name_parts[1].parse::<u32>() == Ok(nft_id)
		{
			match name_parts[2].parse::<u32>() {
				Ok(block_number) => {
					debug!(
						"QUERY NFTID FILE : file exists, nft_id : {}, updated on block {}",
						nft_id, block_number
					);
					return Ok(block_number);
				},
				Err(e) => {
					let message = format!("QUERY NFTID FILE : Key-share exists, nft_id : {}, can not parse block number {:?} : {:?}", nft_id, name_parts[2], e);
					warn!(message);
					return Err(anyhow!(message));
				},
			};
		}
	}

	Ok(0)
}


pub fn query_keyshare_file(dir_path: String) -> Result<BTreeMap<u32,u32>, anyhow::Error> {
	let mut available_keys = BTreeMap::<u32,u32>::new();

	let dir_iterator = match std::fs::read_dir(dir_path) {
		Ok(it) => it,
		Err(e) => {
			// It's better to have a error response
			let message = format!("QUERY KEYSHARE FILE : error reading seales directory {:?}", e);
			error!(message);
			return Err(anyhow!(message));
		},
	};

	for direntry in dir_iterator {
		let entry = match direntry {
			Ok(entry) => entry,
			// It's better to report Internal Error
			Err(e) => {
				error!("QUERY KEYSHARE FILE : error reading directory entry {:?}", e);
				continue;
			},
		};

		let path = entry.path();

		let name_parts: Vec<&str> = match path.file_stem().and_then(std::ffi::OsStr::to_str) {
			Some(name) => name.split('_').collect(),
			None => continue,
		};

		let file_ext = match path.extension().and_then(std::ffi::OsStr::to_str) {
			Some(ext) => ext,
			None => continue,
		};

		if file_ext == "keyshare"
			&& name_parts.len() == 3
			&& (name_parts[0] == "nft" || name_parts[0] == "capsule") {
			
			let nftid = match name_parts[1].parse::<u32>() {
				Ok(nftid) => nftid,
				Err(e) => {
					let message = format!("QUERY KEYSHARE FILE : can not parse nftid {:?} : {:?}", name_parts, e);
					error!(message);
					continue
				},
			};

			let blocknumber = match name_parts[2].parse::<u32>() {
				Ok(blocknumber) => blocknumber,
				Err(e) => {
					let message = format!("QUERY KEYSHARE FILE : can not parse blocknumber {:?} : {:?}", name_parts, e);
					error!(message);
					continue
				},
			};

			available_keys.insert(nftid, blocknumber);
		}
	}

	Ok(available_keys)
}

