use std::{
	fs,
	io::{self, prelude::*, Seek, Write},
	iter::Iterator,
};
use tracing::{error, info, debug};
use zip::{result::ZipError, write::FileOptions};

use std::{fs::File, path::Path};
use walkdir::{DirEntry, WalkDir};

const METHOD_DEFLATED: Option<zip::CompressionMethod> = Some(zip::CompressionMethod::Deflated);

pub fn add_list_zip(src_dir: &str, nftids: Vec<String>, dst_file: &str) -> i32 {
	match doit(src_dir, nftids, dst_file, METHOD_DEFLATED.unwrap()) {
		Ok(_) => {
			tracing::info!(
				"NFTID-based backup compression done: {} written to {}",
				src_dir,
				dst_file
			)
		},
		Err(e) => tracing::error!("Error NFTID-based backup : add_list_zip : {:?}", e),
	}

	0
}

pub fn add_dir_zip(src_dir: &str, dst_file: &str) -> i32 {
	match doit(src_dir, Vec::<String>::new(), dst_file, METHOD_DEFLATED.unwrap()) {
		Ok(_) => {
			tracing::info!("bulk backup compression done: {} written to {}", src_dir, dst_file)
		},
		Err(e) => tracing::error!("Error bulk backup : add_dir_zip : {:?}", e),
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
	debug!("\t ZIPDIR => nft-list = {:?}\n",list);
	
	let mut buffer = Vec::new();
	for entry in it {
		let path = entry.path();
		let name = path.strip_prefix(Path::new(prefix)).unwrap();

		// NFTID-based backup?
		if !list.is_empty() {
			// Wildcard for Synching in maintenacne mode
			if list[0] == "*" {
				// Filter out the enclave_account.key and log files
				let name_parts: Vec<&str> = name.to_str().unwrap().split('.').collect();
				debug!("\t ZIPDIR => name = {:?}, name-parts = {:?}",name, name_parts);
				if name_parts.len() != 2 || name_parts[1] == "log" || name_parts[1] == "key" {
					continue;
				}
			}
			// Synching in Runtime mode Or Admin NFTID backup
			else {
				let name_parts: Vec<&str> = name.to_str().unwrap().split('_').collect();
				// Keyshare file name  = [nft/capsule]_[nftid]_[blocknumber].keyshare
				if name_parts.len() < 2 || !list.contains(&name_parts[1].to_string()) {
					continue;
				}
			}
		}

		// Write file or directory explicitly
		// Some unzip tools unzip files with directory paths correctly, some do not!
		if path.is_file() {
			tracing::debug!("adding file {:?} as {:?} ...", path, name);
			#[allow(deprecated)]
			zip.start_file_from_path(name, options)?;
			let mut f = File::open(path)?;

			f.read_to_end(&mut buffer)?;
			zip.write_all(&buffer)?;
			buffer.clear();
		} else if !name.as_os_str().is_empty() {
			// Only if not root! Avoids path spec / warning
			// and mapname conversion failed error on unzip
			tracing::debug!("adding dir {:?} as {:?} ...", path, name);
			#[allow(deprecated)]
			zip.add_directory_from_path(name, options)?;
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
		Err(e) => {
			error!("Backup extract error opening zip file : {:?}", e);
			return Err(ZipError::Io(e));
		},
	};

	let mut archive = match zip::ZipArchive::new(infile) {
		Ok(archive) => archive,
		Err(e) => {
			error!("Backup extract : error opening file as zip-archive: {:?}", e);
			return Err(e);
		},
	};

	for i in 0..archive.len() {
		let mut file = match archive.by_index(i) {
			Ok(file) => file,
			Err(e) => {
				error!("Backup extract : error opening internal file at index {} : {:?}", i, e);
				return Err(e);
			},
		};

		let outpath = match file.enclosed_name() {
			Some(path) => path.to_owned(),
			None => continue,
		};

		let fullpath_str = outdir.to_string() + outpath.to_str().unwrap();
		let fullpath = Path::new(&fullpath_str);

		if (*file.name()).contains("__MACOSX") {
			continue;
		}

		// DIRECTORY
		if (*file.name()).ends_with('/') {
			match fs::create_dir_all(fullpath) {
				Ok(_file) => info!("create {:?}", fullpath),
				Err(e) => {
					error!("Backup extract : error create internal directory : {:?}", e);
					return Err(zip::result::ZipError::Io(e));
				},
			}
		}
		// FILE
		else {
			// Create Parent Directory of the file if not exists
			if let Some(p) = fullpath.parent() {
				if !p.exists() {
					match fs::create_dir_all(p) {
						Ok(_file) => info!("create {:?}", p),
						Err(e) => {
							error!("Backup extract : error creating paretn directory : {:?}", e);
							return Err(zip::result::ZipError::Io(e));
						},
					}
				}
			}

			// Overwrite the file
			let mut outfile = match fs::File::create(fullpath) {
				Ok(file) => {
					info!("create {:?}", fullpath);
					file
				},
				Err(e) => {
					error!("Backup extract : error (re)creating the file : {:?}", e);
					return Err(zip::result::ZipError::Io(e));
				},
			};

			match io::copy(&mut file, &mut outfile) {
				Ok(n) => info!("successfuly copied {} bytes", n),
				Err(e) => {
					error!("Backup extract : error copying data to file : {:?}", e);
					return Err(zip::result::ZipError::Io(e));
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
