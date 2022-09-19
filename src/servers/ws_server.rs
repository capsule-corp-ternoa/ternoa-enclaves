use crate::server_common;

use axum::{
	extract::{
		ws::{Message, WebSocket, WebSocketUpgrade},
		TypedHeader,
	},
	//handler::Handler,
	response::IntoResponse,
	routing::get,
	Router,
};

use tower_http::trace::{DefaultMakeSpan, TraceLayer};

/* WebSocket Server */
pub async fn ws_server(port: &u16) {
	let ws_app = Router::new()
		// routes are matched from bottom to top, so we have to
		// put `nest` at the top since it matches all routes
		.route("/", get(ws_handler))
		.layer(
			TraceLayer::new_for_http()
				.make_span_with(DefaultMakeSpan::default().include_headers(true)),
		);

	server_common::serve(ws_app, port).await;
}

/* Sample Handler */
async fn ws_handler(
	ws: WebSocketUpgrade,
	user_agent: Option<TypedHeader<headers::UserAgent>>,
) -> impl IntoResponse {
	if let Some(TypedHeader(user_agent)) = user_agent {
		println!("`{}` connected", user_agent.as_str());
	}

	ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
	if let Some(msg) = socket.recv().await {
		if let Ok(msg) = msg {
			match msg {
				Message::Text(t) => {
					println!("client sent str: {:?}", t);
				},
				Message::Binary(_) => {
					println!("client sent binary data");
				},
				Message::Ping(_) => {
					println!("socket ping");
				},
				Message::Pong(_) => {
					println!("socket pong");
				},
				Message::Close(_) => {
					println!("client disconnected");
					return
				},
			}
		} else {
			println!("client disconnected");
			return
		}
	}

	loop {
		if socket.send(Message::Text(String::from("Hi!"))).await.is_err() {
			println!("client disconnected");
			return
		}
		tokio::time::sleep(std::time::Duration::from_secs(3)).await;
	}
}
