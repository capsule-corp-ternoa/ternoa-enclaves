// tests : $ curl 'http://127.0.0.1:4000/rpc' -POST -d '{"jsonrpc": "2.0", "method": "add", "params": [7,17], "id": 1}' -H 'Content-Type: application/json'

use crate::server_common;
use axum::{extract::ContentLengthLimit, response::IntoResponse, routing::post, Router};
use axum_jrpc::{
	error::{JsonRpcError, JsonRpcErrorReason},
	JsonRpcExtractor, JsonRpcResponse,
};

use serde::Deserialize;

/* RPC Server */
pub async fn rpc_server(port: &u16) {
	let rpc_app = Router::new().route("/rpc", post(jsonrpc_handler));
	server_common::serve(rpc_app, port).await;
}

/* Sample Handler */
async fn jsonrpc_handler(
	ContentLengthLimit(value): ContentLengthLimit<JsonRpcExtractor, 1024>,
) -> impl IntoResponse {
	let answer_id = value.get_answer_id();
	println!("{:?}", value);
	match value.method.as_str() {
		"add" => {
			let request: Test = value.parse_params().unwrap();
			let result = request.a + request.b;
			Ok(JsonRpcResponse::success(answer_id, result))
		},
		"sub" => {
			let result: [i32; 2] = value.parse_params().unwrap();
			let result = match failing_sub(result[0], result[1]).await {
				Ok(result) => result,
				Err(e) => {
					return Err(JsonRpcResponse::error(
						answer_id,
						// It is better to Implement <anyhow::Error> for JsonRpcError
						JsonRpcError::new(
							JsonRpcErrorReason::ServerError(-32099),
							e.to_string(),
							serde_json::Value::Null,
						),
					))
				},
			};
			Ok(JsonRpcResponse::success(answer_id, result))
		},
		"div" => {
			let result: [i32; 2] = value.parse_params().unwrap();
			let result = match failing_div(result[0], result[1]).await {
				Ok(result) => result,
				Err(e) => return Err(JsonRpcResponse::error(answer_id, e.into())),
			};

			Ok(JsonRpcResponse::success(answer_id, result))
		},
		method => Ok(value.method_not_found(method)),
	}
}

async fn failing_sub(a: i32, b: i32) -> anyhow::Result<i32> {
	anyhow::ensure!(a > b, "a must be greater than b");
	Ok(a - b)
}

async fn failing_div(a: i32, b: i32) -> Result<i32, CustomDivError> {
	if b == 0 {
		Err(CustomDivError::DivideByZero)
	} else {
		Ok(a / b)
	}
}

#[derive(Deserialize, Debug)]
struct Test {
	a: i32,
	b: i32,
}

#[derive(Debug, thiserror::Error)]
enum CustomDivError {
	#[error("Divisor must not be equal to 0")]
	DivideByZero,
}

impl From<CustomDivError> for JsonRpcError {
	fn from(error: CustomDivError) -> Self {
		JsonRpcError::new(
			JsonRpcErrorReason::ServerError(-32099),
			error.to_string(),
			serde_json::Value::Null,
		)
	}
}
