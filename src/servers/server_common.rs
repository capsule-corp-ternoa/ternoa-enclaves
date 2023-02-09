use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use tracing::info;

/* Secure Server powered by Hyper */

pub async fn serve(app: Router, port: &u16, certfile: &str, keyfile: &str) {
	let socket_addr = SocketAddr::from(([0, 0, 0, 0], *port));

	tracing::info!("listening on {}", socket_addr);

	let config = match RustlsConfig::from_pem_file(certfile, keyfile).await {
		Ok(conf) => conf,
		Err(e) => {
			panic!("Error in server config : {}, path1 = {}, path2 = {}", e, certfile, keyfile)
		},
	};

	info!("Server is listening {} on Port {}'\n", socket_addr.ip(), socket_addr.port());

	let server = axum_server::bind_rustls(socket_addr, config)
		.serve(app.into_make_service())
		.await;

	match server {
		Ok(_) => info!("Server finished successfully"),
		Err(e) => info!("Error in sgx server : {}", e),
	}
}
