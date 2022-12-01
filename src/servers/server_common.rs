use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

/* Secure Server powered by Hyper */

pub async fn serve(app: Router, port: &u16) {
	let socket_addr = SocketAddr::from(([0, 0, 0, 0], *port));

	tracing::info!("listening on {}", socket_addr);

	let config = RustlsConfig::from_pem_file(
		"credentials/certificates/server_cert.pem",
		"credentials/certificates/server_key.pem",
	)
	.await
	.unwrap();

	println!("Server is listening {} on Port {}'\n", socket_addr.ip(), socket_addr.port());

	/*
		axum::Server::bind(&socket_addr)
			.serve(app.into_make_service())
			.await
			.unwrap();
	*/

	axum_server::bind_rustls(socket_addr, config)
		.serve(app.into_make_service())
		.await
		.unwrap();
}
