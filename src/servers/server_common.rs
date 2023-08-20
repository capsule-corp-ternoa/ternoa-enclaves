use rustls::ServerConfig;
use rustls_acme::{caches::DirCache, AcmeConfig};
use std::{
	net::{Ipv4Addr, SocketAddr},
	path::PathBuf,
	sync::Arc,
	time::Duration,
};
use tokio::time::sleep;

use tokio_stream::StreamExt;

use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};

use tracing::{debug, error, info};

/// Servers the server
/// # Arguments
/// * `app` - The app to serve
/// * `domain` - The domain to serve
/// * `port` - The port to serve
/// # Returns
/// * `Result<(), anyhow::Error>` - The result of the server
pub async fn serve(app: Router, domain: &str, port: &u16) -> Result<(), anyhow::Error> {
	info!("SERVER INITIALIZATION : Startng server with app, domain, port.");

	let socket_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443));

	info!("SERVER INITIALIZATION : starting certificate server on {}", socket_addr);

	let mut state = AcmeConfig::new([domain])
		.contact(
			["amin@capsule-corp.io", "soufiane@capsule-corp.io"]
				.iter()
				.map(|err| format!("mailto:{}", err)),
		)
		.cache_option(Some(DirCache::new(PathBuf::from(r"/certificates/"))))
		.directory_lets_encrypt(cfg!(any(feature = "main-net", feature = "alpha-net")))
		.state();

	info!("SERVER INITIALIZATION : define rust-TLS config.");
	let rustls_config = ServerConfig::builder()
		.with_safe_defaults()
		.with_no_client_auth()
		.with_cert_resolver(state.resolver());

	let acceptor = state.axum_acceptor(Arc::new(rustls_config.clone()));

	info!("SERVER INITIALIZATION : spawn cert state");
	tokio::spawn(async move {
		loop {
			match state.next().await {
				Some(evt) => match evt {
					Ok(ok) => info!("SERVER INITIALIZATION : SPAWN CERT EVENT : {:?}", ok),
					Err(err) => {
						error!("SERVER INITIALIZATION : SPAWN CERT EVENT : ERROR: {err:?}")
					},
				},
				None => error!("SERVER INITIALIZATION : SPAWN CERT EVENT : error get event"),
			}
		}
	});

	let config = RustlsConfig::from_config(Arc::new(rustls_config.clone()));

	let dummy_app =
		Router::new().route("/", axum::routing::get(|| async { "Server is updating!" }));

	// Spawn a task to shutdown server.
	let handle = Handle::new();
	tokio::spawn(cert_shutdown(handle.clone()));

	info!("SERVER INITIALIZATION : start cert server");
	let cert_server = axum_server::bind_rustls(socket_addr, config.clone())
		.acceptor(acceptor.clone())
		.handle(handle)
		.serve(dummy_app.into_make_service())
		.await;
	info!(
		"SERVER INITIALIZATION : Certificate Server is listening {} on Port 443, \nwait a minute please ...'\n",
		socket_addr.ip()
	);

	//cert_shutdown(handle).await;
	info!("SERVER INITIALIZATION : cert server shutdown");

	match cert_server {
		Ok(_) => {
			info!("SERVER INITIALIZATION : Certificate Server finished successfully");
		},

		Err(err) => {
			info!("SERVER INITIALIZATION : Error in certificate server : {}", err);
			return Err(anyhow::anyhow!(format!(
				"SERVER INITIALIZATION : Error in certificate server : {err}"
			)));
		},
	}

	let socket_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, *port));
	info!("SERVER INITIALIZATION : SGX Server is listening {}'\n", socket_addr);

	let sgx_server_handle = axum_server::bind_rustls(socket_addr, config)
		//.acceptor(acceptor)
		.serve(app.into_make_service_with_connect_info::<SocketAddr>());

	// DOES IT MAKE SENSE? SINCE AXUM IS INSIDE TOKIO THREAD IN MAIN FUNCTION!
	//let sgx_server = tokio::spawn(sgx_server_handle);

	debug!("SERVER INITIALIZATION : server exit\n");
	//match tokio::try_join!(sgx_server) {
	match sgx_server_handle.await {
		Ok(_) => {
			info!("SERVER INITIALIZATION : SGX Server finished successfully");
			Ok(())
		},

		Err(err) => {
			error!("SERVER INITIALIZATION : Error in SGX server : {}", err);
			Err(anyhow::anyhow!(format!("SERVER INITIALIZATION : Error in sgx server : {err}")))
		},
	}
}

/// Shutdown the server
/// # Arguments
/// * `handle` - The handle to shutdown the server
async fn cert_shutdown(handle: Handle) {
	// Wait 20 seconds.
	info!("SERVER INITIALIZATION : wait 20 seconds before shutdown cert server");
	sleep(Duration::from_secs(20)).await;

	info!("SERVER INITIALIZATION : sending shutdown signal to Certificate server");

	// Signal the server to shutdown using Handle.
	handle.shutdown();

	info!("SERVER INITIALIZATION : Certificate server is down.");
}
