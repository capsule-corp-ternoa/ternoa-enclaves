use rustls::ServerConfig;
use rustls_acme::{caches::DirCache, AcmeConfig};
use std::{
	net::{Ipv4Addr, SocketAddr},
	path::PathBuf,
	sync::Arc,
};

use tokio_stream::StreamExt;

use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};

use tracing::{debug, error, info};

pub async fn serve(app: Router, domain: &str, port: &u16) -> Result<(), anyhow::Error> {
	debug!("3-5-1 Startng server with app, domain, port.");

	let socket_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443));

	info!("starting certificate server on {}", socket_addr);

	let mut state = AcmeConfig::new([domain])
		.contact(
			["amin@capsule-corp.io", "soufiane@capsule-corp.io"]
				.iter()
				.map(|e| format!("mailto:{}", e.to_owned())),
		)
		.cache_option(Some(DirCache::new(PathBuf::from(r"/certificates/"))))
		.directory_lets_encrypt(true)
		.state();

	debug!("3-5-2 Startng server : define rust-TLS config.");
	let rustls_config = ServerConfig::builder()
		.with_safe_defaults()
		.with_no_client_auth()
		.with_cert_resolver(state.resolver());

	let acceptor = state.axum_acceptor(Arc::new(rustls_config.clone()));

	debug!("3-5-3 Startng server : spawn cert state");
	tokio::spawn(async move {
		loop {
			match state.next().await.unwrap() {
				Ok(ok) => info!("event: {:?}", ok),
				Err(err) => error!("error: {:?}", err),
			}
		}
	});

	let config = RustlsConfig::from_config(Arc::new(rustls_config.clone()));

	let dummy_app =
		Router::new().route("/", axum::routing::get(|| async { "Server is updating!" }));

	// Spawn a task to shutdown server.
	let handle = Handle::new();
	//tokio::spawn(cert_shutdown(handle));

	debug!("3-5-4 Startng server : start cert server");
	let cert_server = axum_server::bind_rustls(socket_addr, config.clone())
		.acceptor(acceptor.clone())
		.handle(handle.clone())
		.serve(dummy_app.into_make_service())
		.await;
	info!(
		"Certificate Server is listening {} on Port 443, \nwait a minute please ...'\n",
		socket_addr.ip()
	);

	cert_shutdown(handle).await;
	debug!("3-5-5 Startng server : cert server shutdown");

	match cert_server {
		Ok(_) => {
			info!("Certificate Server finished successfully");
		},

		Err(e) => {
			info!("Error in certificate server : {}", e);
			return Err(anyhow::anyhow!(format!("Error in certificate server : {e}")))
		},
	}

	let socket_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, *port));
	debug!("3-5-6 Startng server : starting server \n");
	info!("SGX Server is listening {}'\n", socket_addr);

	let sgx_server = axum_server::bind_rustls(socket_addr, config)
		//.acceptor(acceptor)
		.serve(app.into_make_service())
		.await;

	debug!("3-5-7 Startng server : server exit\n");
	match sgx_server {
		Ok(_) => {
			info!("SGX Server finished successfully");
			Ok(())
		},

		Err(e) => {
			info!("Error in SGX server : {}", e);
			Err(anyhow::anyhow!(format!("Error in sgx server : {e}")))
		},
	}
}

async fn cert_shutdown(handle: Handle) {
	// Wait 20 seconds.
	//sleep(Duration::from_secs(20)).await;

	info!("sending shutdown signal to Certificate server");

	// Signal the server to shutdown using Handle.
	handle.shutdown();

	info!("Certificate server is down.");
}
