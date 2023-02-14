use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use tracing::info;
use rcgen;
use rcgen::generate_simple_self_signed;

/* Secure Server powered by Hyper */

pub async fn serve(app: Router, port: &u16, certfile: &str, keyfile: &str) {
	let socket_addr = SocketAddr::from(([0, 0, 0, 0], *port));

	tracing::info!("listening on {}", socket_addr);
	
	let file = std::fs::File::open("/etc/hosts").unwrap();
    let lines = std::io::BufRead::lines(std::io::BufReader::new(file));
	let domains: Vec<String> = lines.last().unwrap().unwrap().split("\t").map(|s| s.to_string()).collect();

	let certificate = generate_simple_self_signed(domains).unwrap();
	
	let cert_pem = certificate.serialize_pem().expect("Error in certificate serialization to pem format");
	let cert_key = certificate.serialize_private_key_pem();

	//std::fs::write("/nft/certfile.pem", cert_pem).expect("Can not write certificate to sealed folder.");
	//std::fs::write("/nft/keyfile.pem", cert_key).expect("Can not write certificate-key to sealed folder.");

	let config = match RustlsConfig::from_pem(cert_pem.as_bytes().to_vec(), cert_key.as_bytes().to_vec()).await {
		Ok(conf) => conf,
		Err(e) => {
			panic!("Error in server config : {}, path1 = {}, path2 = {}", e, certfile, keyfile)
		},
	};

	/*
	let config = match RustlsConfig::from_pem_file(certfile, keyfile).await {
		Ok(conf) => conf,
		Err(e) => {
			panic!("Error in server config : {}, path1 = {}, path2 = {}", e, certfile, keyfile)
		},
	};
	*/
	
	info!("Server is listening {} on Port {}'\n", socket_addr.ip(), socket_addr.port());

	let server = axum_server::bind_rustls(socket_addr, config)
		.serve(app.into_make_service())
		.await;

	match server {
		Ok(_) => info!("Server finished successfully"),
		Err(e) => info!("Error in sgx server : {}", e),
	}
}
