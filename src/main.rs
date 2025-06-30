use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use std::io;
use std::str::FromStr;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

// API 1: Generate Keypair
async fn generate_keypair() -> impl IntoResponse {
    let key_pair = Keypair::new();
    let pubkey = key_pair.pubkey().to_string();
    let secret_bytes = key_pair.to_bytes();
    let secret = bs58::encode(secret_bytes).into_string();

    let response_data = serde_json::json!({
        "pubkey": pubkey,
        "secret": secret
    });
    Json(ApiResponse::success(response_data))
}

async fn create_token(Json(payload): Json<CreateTokenRequest>) -> impl IntoResponse {
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error(
                    "fool me once shame on you".to_string(),
                )),
            );
        }
    };

    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error(
                    "fool me twice,can't put the blame on you".to_string(),
                )),
            );
        }
    };

    // For now, let's create a basic response structure
    // We'll need spl-token crate for the actual instruction data
    let response_data = serde_json::json!({
        "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token Program ID
        "accounts": [
            {
                "pubkey": mint_pubkey.to_string(),
                "is_signer": false,
                "is_writable": true
            },
            {
                "pubkey": "SysvarRent111111111111111111111111111111111", // Rent sysvar
                "is_signer": false,
                "is_writable": false
            }
        ],
        "instruction_data": "placeholder_instruction_data" // We'll implement this properly later
    });

    (StatusCode::OK, Json(ApiResponse::success(response_data)))
}

async fn mint_token(Json(payload): Json<MintTokenRequest>) -> impl IntoResponse {
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error(
                    "fool me three times, you're officially an idiot".to_string(),
                )),
            );
        }
    };

    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error(
                    "destination unknown, like my future".to_string(),
                )),
            );
        }
    };

    let authority_pubkey = match Pubkey::from_str(&payload.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error(
                    "no authority detected, just like my life".to_string(),
                )),
            );
        }
    };

    if payload.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error("zero amount? sheesh".to_string())),
        );
    }

    let response_data = serde_json::json!({
        "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "accounts": [
            {
                "pubkey": mint_pubkey.to_string(),
                "is_signer": false,
                "is_writable": true
            },
            {
                "pubkey": destination_pubkey.to_string(),
                "is_signer": false,
                "is_writable": true
            },
            {
                "pubkey": authority_pubkey.to_string(),
                "is_signer": true,
                "is_writable": false
            }
        ],
        "instruction_data": "mint_tokens_instruction_placeholder"
    });

    (StatusCode::OK, Json(ApiResponse::success(response_data)))
}

async fn sign_message() -> impl IntoResponse {
    Json(ApiResponse::<()>::error("Not implemented yet".to_string()))
}

async fn verify_message() -> impl IntoResponse {
    Json(ApiResponse::<()>::error("Not implemented yet".to_string()))
}

async fn send_sol() -> impl IntoResponse {
    Json(ApiResponse::<()>::error("Not implemented yet".to_string()))
}

async fn send_token() -> impl IntoResponse {
    Json(ApiResponse::<()>::error("Not implemented yet".to_string()))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));
    let addr = format!("0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
