use std::{
	fs,
	io::{self, prelude::*, Seek, Write},
	iter::Iterator,
};
use tracing::{debug, error, info, warn};
use zip::{result::ZipError, write::FileOptions};

use std::{fs::File, path::Path};
use walkdir::{DirEntry, WalkDir};

const METHOD_DEFLATED: zip::CompressionMethod = zip::CompressionMethod::Deflated;

pub fn add_list_zip(src_dir: &str, nftids: Vec<String>, dst_file: &str) -> i32 {
	match doit(src_dir, nftids, dst_file, METHOD_DEFLATED) {
		Ok(_) => {
			tracing::info!(
				"NFTID-based backup compression done: {} written to {}",
				src_dir,
				dst_file
			)
		},
		Err(err) => tracing::error!("Error NFTID-based backup : add_list_zip : {err:?}"),
	}

	0
}

pub fn add_dir_zip(src_dir: &str, dst_file: &str) -> i32 {
	match doit(src_dir, Vec::<String>::new(), dst_file, METHOD_DEFLATED) {
		Ok(_) => {
			tracing::info!("bulk backup compression done: {} written to {}", src_dir, dst_file)
		},
		Err(err) => tracing::error!("Error bulk backup : add_dir_zip : {err:?}"),
	}

	0
}

fn zip_dir<T>(
	it: &mut dyn Iterator<Item = DirEntry>,
	list: Vec<String>,
	prefix: &str,
	writer: T,
	method: zip::CompressionMethod,
) -> zip::result::ZipResult<()>
where
	T: Write + Seek,
{
	let mut zip = zip::ZipWriter::new(writer);
	let options = FileOptions::default().compression_method(method).unix_permissions(0o755);
	debug!("\t ZIPDIR => nft-list = {:?}\n", list);

	let mut buffer = Vec::new();
	for entry in it {
		let path = entry.path();

		let file_ext = match path.extension().and_then(std::ffi::OsStr::to_str) {
			Some(ext) => ext,
			None => {
				warn!("ZIPDIR => CAN NOT extract file-extention from {:?}", path);
				continue;
			},
		};

		let file_name = match path.file_stem().and_then(std::ffi::OsStr::to_str) {
			Some(name) => name,
			None => {
				warn!("ZIPDIR => CAN NOT extract file-name from {:?}", path);
				continue;
			},
		};

		let name_ext = match path.strip_prefix(Path::new(prefix)) {
			Ok(ne) => ne,
			Err(err) => {
				error!(
					"ZIPDIR => CAN NOT STRIP PATH PREFIX {:?} OF PATH {:?} : {:?}",
					prefix, path, err
				);
				continue;
			},
		};

		// NFTID-based backup? (vs Admin Full-Backup)
		if !list.is_empty() {
			// Wildcard for Synching in maintenacne mode
			if list[0] == "*" {
				// Filter out the enclave_account.key and log files
				debug!("\t ZIPDIR : WILDCARD : file-name = {:?}", name_ext);

				if file_ext.is_empty() || file_ext != "keyshare" {
					debug!(
						"\t ZIPDIR => improper file-extension for synchronization = {:?}",
						name_ext
					);
					continue;
				}
			} else {
				// Synching in Runtime mode Or Admin NFTID backup
				let name_parts: Vec<&str> = file_name.split('_').collect();

				// Keyshare file name  = [nft/capsule]_[nftid]_[blocknumber].keyshare
				debug!("\t ZIPDIR => nameparts = {:?}, list = {:?}\n", name_parts, list);

				// File Name : NFT_NFTID_BLOCKNUMBER : nft_123_2345
				if file_ext.is_empty()
					|| file_ext != "keyshare"
					|| name_parts.len() != 3
					|| !list.contains(&name_parts[1].to_string())
				{
					debug!(
						"\t ZIPDIR => improper file name-parts for synchronization = {:?}",
						name_parts
					);
					continue;
				}
			}
		}

		// Write file or directory explicitly
		// Some unzip tools unzip files with directory paths correctly, some do not!
		if path.is_file() {
			debug!("\t ZIPDIR => adding file {:?} as {:?} ...", path, name_ext);
			#[allow(deprecated)]
			zip.start_file_from_path(name_ext, options)?;
			let mut f = File::open(path)?;

			f.read_to_end(&mut buffer)?;
			zip.write_all(&buffer)?;
			buffer.clear();
		} else if !name_ext.as_os_str().is_empty() {
			// Only if not root! Avoids path spec / warning
			// and mapname conversion failed error on unzip
			tracing::debug!("\t ZIPDIR => adding dir {:?} as {:?} ...", path, name_ext);
			#[allow(deprecated)]
			zip.add_directory_from_path(name_ext, options)?;
		}
	}

	zip.finish()?;
	Result::Ok(())
}

/// Compresses a directory into a zip file
fn doit(
	src_dir: &str,
	list: Vec<String>,
	dst_file: &str,
	method: zip::CompressionMethod,
) -> zip::result::ZipResult<()> {
	//debug!("zip doit :src_dir = {}, ",src_dir, );
	if !Path::new(src_dir).is_dir() {
		return Err(ZipError::FileNotFound);
	}
	let path = Path::new(dst_file);
	//debug!("zip doit : file = {:?}, ", path);
	let file = File::create(path)?;

	let walkdir = WalkDir::new(src_dir).max_depth(1);
	let it = walkdir.into_iter();

	zip_dir(&mut it.filter_map(|e| e.ok()), list, src_dir, file, method)?;

	Ok(())
}

/* ----------------------------
		EXTRACT ARCHIVE
-------------------------------*/
pub fn zip_extract(filename: &str, outdir: &str) -> Result<(), ZipError> {
	let fname = std::path::Path::new(filename);

	let infile = match fs::File::open(fname) {
		Ok(file) => file,
		Err(err) => {
			error!("Backup extract : error opening zip file : {err:?}");
			return Err(ZipError::Io(err));
		},
	};

	let mut archive = match zip::ZipArchive::new(infile) {
		Ok(archive) => archive,
		Err(err) => {
			error!("Backup extract : error opening file as zip-archive: {err:?}");
			return Err(err);
		},
	};

	for i in 0..archive.len() {
		let mut file = match archive.by_index(i) {
			Ok(file) => file,
			Err(err) => {
				error!("Backup extract : error opening internal file at index {} : {:?}", i, err);
				return Err(err);
			},
		};

		let outpath = match file.enclosed_name() {
			Some(path) => path.to_owned(),
			None => {
				error!("Backup extract : error get enclosed-name of file from zip index {}", i);
				continue;
			},
		};

		let fullpath_str =
			outdir.to_string()
				+ match outpath.to_str() {
					Some(st) => st,
					None => {
						error!("Backup extract : error converting path to str  index = {}, path = {:?}", i, outpath);
						continue;
					},
				};

		let fullpath = Path::new(&fullpath_str);

		if (*file.name()).contains("__MACOSX") {
			continue;
		}

		// DIRECTORY
		if (*file.name()).ends_with('/') {
			match fs::create_dir_all(fullpath) {
				Ok(_file) => info!("Backup extract : create directory {:?}", fullpath),
				Err(err) => {
					error!("Backup extract : error create internal directory : {err:?}");
					return Err(zip::result::ZipError::Io(err));
				},
			}
		}
		// FILE
		else {
			// Create Parent Directory of the file if not exists
			if let Some(p) = fullpath.parent() {
				if !p.exists() {
					match fs::create_dir_all(p) {
						Ok(_file) => info!("Backup extract : create {:?}", p),
						Err(err) => {
							error!("Backup extract : error creating paretn directory : {err:?}");
							return Err(zip::result::ZipError::Io(err));
						},
					}
				}
			}

			// Overwrite the file
			let mut outfile = match fs::File::create(fullpath) {
				Ok(file) => {
					info!("Backup extract : create {:?}", fullpath);
					file
				},
				Err(err) => {
					error!("Backup extract : error (re)creating the file : {err:?}");
					return Err(zip::result::ZipError::Io(err));
				},
			};

			match io::copy(&mut file, &mut outfile) {
				Ok(n) => info!("successfuly copied {} bytes", n),
				Err(err) => {
					error!("Backup extract : error copying data to file : {err:?}");
					return Err(zip::result::ZipError::Io(err));
				},
			}
		}

		// Get and Set permissions
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;

			if let Some(mode) = file.unix_mode() {
				fs::set_permissions(fullpath, fs::Permissions::from_mode(mode))?;
			}
		}
	}

	Ok(())
}

#[cfg(test)]
mod test {

	use super::*;

	#[tokio::test]
	async fn zip_list_test() {
		let nftids = vec!["11", "25", "141", "330"].iter().map(|s| s.to_string()).collect();
		add_list_zip("/tmp", nftids, "/tmp/zip/backup2.zip");
		let _ = zip_extract("/tmp/zip/backup2.zip", "/tmp/test2/");
	}

	#[tokio::test]
	async fn zip_dir_test() {
		add_dir_zip("/tmp", "/tmp/zip/backup1.zip");
		let _ = zip_extract("/tmp/zip/backup1.zip", "/tmp/test1/");
	}
}
