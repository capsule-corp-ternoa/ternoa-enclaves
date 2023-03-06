use std::{
	fs,
	io::{self, prelude::*, Seek, Write},
	iter::Iterator,
};
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
			zip.start_file_from_path(name, options).unwrap();
			let mut f = File::open(path).unwrap();

			f.read_to_end(&mut buffer).unwrap();
			zip.write_all(&buffer).unwrap();
			buffer.clear();
		} else if !name.as_os_str().is_empty() {
			// Only if not root! Avoids path spec / warning
			// and mapname conversion failed error on unzip
			tracing::info!("adding dir {:?} as {:?} ...", path, name);
			#[allow(deprecated)]
			zip.add_directory_from_path(name, options).unwrap();
		}
	}
	zip.finish().unwrap();
	Result::Ok(())
}

fn doit(
	src_dir: &str,
	dst_file: &str,
	method: zip::CompressionMethod,
) -> zip::result::ZipResult<()> {
	if !Path::new(src_dir).is_dir() {
		return Err(ZipError::FileNotFound)
	}

	let path = Path::new(dst_file);
	let file = File::create(path).unwrap();

	let walkdir = WalkDir::new(src_dir);
	let it = walkdir.into_iter();

	zip_dir(&mut it.filter_map(|e| e.ok()), src_dir, file, method).unwrap();

	Ok(())
}

/* ----------------------------
		EXTRACT ARCHIVE
-------------------------------*/
pub fn zip_extract(filename: &str, outdir: &str) {
	let fname = std::path::Path::new(filename);
	let infile = fs::File::open(fname).unwrap();

	let mut archive = zip::ZipArchive::new(infile).unwrap();

	for i in 0..archive.len() {
		let mut file = archive.by_index(i).unwrap();
		let outpath = match file.enclosed_name() {
			Some(path) => path.to_owned(),
			None => continue,
		};

		let fullpath_str = outdir.to_string() + outpath.to_str().unwrap();
		let fullpath = Path::new(&fullpath_str);

		// DIRECTORY
		if (*file.name()).ends_with('/') {
			fs::create_dir_all(fullpath).unwrap();
		} else {
			// FILE
			if let Some(p) = fullpath.parent() {
				if !p.exists() {
					fs::create_dir_all(p).unwrap();
				}
			}
			let mut outfile = fs::File::create(fullpath).unwrap();
			io::copy(&mut file, &mut outfile).unwrap();
		}

		// Get and Set permissions
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;

			if let Some(mode) = file.unix_mode() {
				fs::set_permissions(fullpath, fs::Permissions::from_mode(mode)).unwrap();
			}
		}
	}
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

		zip_extract("/tmp/backup.zip", "/tmp/test/");
	}
}
