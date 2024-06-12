use std::{collections::BTreeMap, path::Path};

use anyhow::anyhow;
use tracing::{debug, error, warn};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NftType {
	Secret,
	Capsule,
	Hybrid,
}

#[derive(Clone, Copy, Debug)]
pub struct Availability {
	pub block_number: u32,
	pub nft_type: NftType,
}

pub fn query_keyshare_file(dir_path: String) -> Result<BTreeMap<u32, Availability>, anyhow::Error> {
	let mut available_keys = BTreeMap::<u32, Availability>::new();

	let dir_iterator = match std::fs::read_dir(dir_path) {
		Ok(it) => it,
		Err(err) => {
			// It's better to have a error response
			let message = format!("QUERY KEYSHARE FILE : error reading seales directory {err:?}");
			error!(message);
			return Err(anyhow!(message));
		},
	};

	for direntry in dir_iterator {
		let entry = match direntry {
			Ok(entry) => entry,
			// It's better to report Internal Error
			Err(err) => {
				error!("QUERY KEYSHARE FILE : error reading directory entry {err:?}");
				continue;
			},
		};

		let path = entry.path();

		if let Ok((nftid, av)) = parse_keyshare_file(&path) {
			if let Some(ks) = available_keys.get(&nftid) {
				let block_number = std::cmp::max(av.block_number, ks.block_number);

				if ks.nft_type != av.nft_type {
					let hybrid_av = Availability { block_number, nft_type: NftType::Hybrid };

					available_keys.insert(nftid, hybrid_av);

					continue;
				}
			}

			available_keys.insert(nftid, av);
		}
	}

	Ok(available_keys)
}

pub fn parse_keyshare_file(path: &Path) -> Result<(u32, Availability), anyhow::Error> {
	//let path = std::path::Path::new(&file_name);

	let name_parts: Vec<&str> = match path.file_stem().and_then(std::ffi::OsStr::to_str) {
		Some(name) => name.split('_').collect(),
		None => return Err(anyhow!("PARSE KEYSHARE FILE-NAME : Can not split file name")),
	};

	let file_ext = match path.extension().and_then(std::ffi::OsStr::to_str) {
		Some(ext) => ext,
		None => return Err(anyhow!("PARSE KEYSHARE FILE-NAME : Can not find the extension")),
	};

	if file_ext != "keyshare" || name_parts.len() != 3 {
		let message = format!("PARSE KEYSHARE FILE-NAME : invalid file name {:?}", name_parts);
		return Err(anyhow!(message));
	}

	let nftid = match name_parts[1].parse::<u32>() {
		Ok(nftid) => nftid,
		Err(err) => {
			let message = format!(
				"PARSE KEYSHARE FILE-NAME : can not parse nftid {:?} : {:?}",
				name_parts, err
			);
			return Err(anyhow!(message));
		},
	};

	let block_number = match name_parts[2].parse::<u32>() {
		Ok(blocknumber) => blocknumber,
		Err(err) => {
			let message = format!(
				"PARSE KEYSHARE FILE-NAME : can not parse blocknumber {:?} : {:?}",
				name_parts, err
			);
			return Err(anyhow!(message));
		},
	};

	let nft_type = match name_parts[0] {
		"nft" => NftType::Secret,
		"capsule" => NftType::Capsule,
		_ => {
			let message = format!("PARSE KEYSHARE FILE-NAME : invalid  nft type {:?}", name_parts);
			return Err(anyhow!(message));
		},
	};

	Ok((nftid, Availability { block_number, nft_type }))
}

pub fn _query_nftid_file(dir_path: String, nft_id: u32) -> Result<u32, anyhow::Error> {
	let dir_iterator = match std::fs::read_dir(dir_path) {
		Ok(it) => it,
		Err(err) => {
			// It's better to have a error response
			let message = format!("QUERY NFTID FILE : error reading seales directory {err:?}");
			error!(message);
			return Err(anyhow!(message));
		},
	};

	for direntry in dir_iterator {
		let entry = match direntry {
			Ok(entry) => entry,
			// It's better to report Internal Error
			Err(err) => {
				error!("QUERY NFTID FILE : error reading directory entry {err:?}");
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
				Err(err) => {
					let message = format!("QUERY NFTID FILE : Key-share exists, nft_id : {}, can not parse block number {:?} : {:?}", nft_id, name_parts, err);
					warn!(message);
					return Err(anyhow!(message));
				},
			};
		}
	}

	Ok(0)
}
