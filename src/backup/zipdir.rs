use std::{
	fs,
	io::{self, prelude::*, Seek, Write},
	iter::Iterator,
};
use tracing::{error, info};
use zip::{result::ZipError, write::FileOptions};

use std::{fs::File, path::Path};
use walkdir::{DirEntry, WalkDir};

const METHOD_DEFLATED: Option<zip::CompressionMethod> = Some(zip::CompressionMethod::Deflated);

pub fn add_dir_zip(src_dir: &str, dst_file: &str) -> i32 {
	match doit(src_dir, dst_file, METHOD_DEFLATED.unwrap()) {
		Ok(_) =>
			tracing::info!("bulk backup compression done: {} written to {}", src_dir, dst_file),
		Err(e) => tracing::info!("Error bulk backup : {:?}", e),
	}

	0
}

fn zip_dir<T>(
	it: &mut dyn Iterator<Item = DirEntry>,
	prefix: &str,
	writer: T,
	method: zip::CompressionMethod,
) -> zip::result::ZipResult<()>
where
	T: Write + Seek,
{
	let mut zip = zip::ZipWriter::new(writer);
	let options = FileOptions::default().compression_method(method).unix_permissions(0o755);

	let mut buffer = Vec::new();
	for entry in it {
		let path = entry.path();
		let name = path.strip_prefix(Path::new(prefix)).unwrap();

		// Write file or directory explicitly
		// Some unzip tools unzip files with directory paths correctly, some do not!
		if path.is_file() {
			tracing::info!("adding file {:?} as {:?} ...", path, name);
			#[allow(deprecated)]
			zip.start_file_from_path(name, options)?;
			let mut f = File::open(path)?;

			f.read_to_end(&mut buffer)?;
			zip.write_all(&buffer)?;
			buffer.clear();
		} else if !name.as_os_str().is_empty() {
			// Only if not root! Avoids path spec / warning
			// and mapname conversion failed error on unzip
			tracing::info!("adding dir {:?} as {:?} ...", path, name);
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
	dst_file: &str,
	method: zip::CompressionMethod,
) -> zip::result::ZipResult<()> {
	if !Path::new(src_dir).is_dir() {
		return Err(ZipError::FileNotFound)
	}
	let path = Path::new(dst_file);
	let file = File::create(path)?;

	let walkdir = WalkDir::new(src_dir);
	let it = walkdir.into_iter();

	zip_dir(&mut it.filter_map(|e| e.ok()), src_dir, file, method)?;

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
			return Err(ZipError::Io(e))
		},
	};

	let mut archive = match zip::ZipArchive::new(infile) {
		Ok(archive) => archive,
		Err(e) => {
			error!("Backup extract error opening file as zip-archive: {:?}", e);
			return Err(e)
		},
	};

	for i in 0..archive.len() {
		let mut file = match archive.by_index(i) {
			Ok(file) => file,
			Err(e) => {
				error!("Backup extract error opening internal file at index {} : {:?}", i, e);
				return Err(e)
			},
		};

		let outpath = match file.enclosed_name() {
			Some(path) => path.to_owned(),
			None => continue,
		};

		let fullpath_str = outdir.to_string() + outpath.to_str().unwrap();
		let fullpath = Path::new(&fullpath_str);

		if (*file.name()).contains("__MACOSX") {
			continue
		}

		// DIRECTORY
		if (*file.name()).ends_with('/') {
			match fs::create_dir_all(fullpath) {
				Ok(_file) => info!("create {:?}", fullpath),
				Err(e) => {
					error!("Backup extract error create internal directory : {:?}", e);
					return Err(zip::result::ZipError::Io(e))
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
							error!("Backup extract error creating paretn directory : {:?}", e);
							return Err(zip::result::ZipError::Io(e))
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
					error!("Backup extract error (re)creating the file : {:?}", e);
					return Err(zip::result::ZipError::Io(e))
				},
			};

			match io::copy(&mut file, &mut outfile) {
				Ok(n) => info!("successfuly copied {} bytes", n),
				Err(e) => {
					error!("Backup extract error copying data to file : {:?}", e);
					return Err(zip::result::ZipError::Io(e))
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

	/* ----------------------
		 PARSING
	---------------------- */
	#[tokio::test]
	async fn zip_test() {
		add_dir_zip("/tmp", "/tmp/backup.zip");

		let _ = zip_extract("/tmp/backup.zip", "/tmp/test/");
	}
}
