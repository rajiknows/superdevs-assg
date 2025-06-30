use crate::models::{
    AccountMetaResponse, ApiResponse, CreateTokenRequest, InstructionResponse, MintTokenRequest,
    SendSolRequest, SendTokenRequest, SignMessageRequest, SignResponse, VerifyMessageRequest,
    VerifyResponse, keypair_response,
};
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::post};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use std::convert::TryFrom;
use std::io;
use std::str::FromStr; // ADDED: For Keypair::try_from

mod models;

fn pubkey_verify(pubkey_str: &str) -> Result<Pubkey, String> {
    if pubkey_str.len() < 32 || pubkey_str.len() > 44 {
        return Err("Pubkey length invalid".to_string());
    }
    Pubkey::from_str(pubkey_str).map_err(|_| "Bad pubkey format".to_string())
}

fn keypair_verify(secret_str: &str) -> Result<Keypair, String> {
    let bytes = bs58::decode(secret_str)
        .into_vec()
        .map_err(|_| "Invalid secret key encoding".to_string())?;

    if bytes.len() != 64 {
        return Err("Secret key length wrong".to_string());
    }

    // UPDATED: Used try_from to resolve deprecation warning and provide better error handling.
    Keypair::try_from(bytes.as_slice()).map_err(|_| "Invalid secret key format".to_string())
}

fn instruction_to_response(instruction: Instruction) -> InstructionResponse {
    InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .into_iter()
            .map(|acc| AccountMetaResponse {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            })
            .collect(),
        instruction_data: BASE64.encode(&instruction.data),
    }
}

async fn generate_keypair() -> (StatusCode, Json<ApiResponse<keypair_response>>) {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    (
        StatusCode::OK,
        Json(ApiResponse::success(keypair_response {
            pubkey,
            // FIX: Corrected field name from 'secret_key' to 'secret' to match models.rs
            secret: secret,
        })),
    )
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionResponse>>) {
    let mint_authority = match pubkey_verify(&payload.mint_authority) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    let mint = match pubkey_verify(&payload.mint) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    if payload.decimals > 9 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Decimals must be between 0 and 9".to_string(),
            )),
        );
    }

    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        payload.decimals,
    ) {
        Ok(instr) => instr,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            );
        }
    };

    (
        StatusCode::OK,
        Json(ApiResponse::success(instruction_to_response(instruction))),
    )
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionResponse>>) {
    let mint = match pubkey_verify(&payload.mint) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    let destination = match pubkey_verify(&payload.destination) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    let authority = match pubkey_verify(&payload.authority) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    if payload.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Amount must be > 0".to_string())),
        );
    }

    let instruction = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ) {
        Ok(instr) => instr,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            );
        }
    };

    (
        StatusCode::OK,
        Json(ApiResponse::success(instruction_to_response(instruction))),
    )
}

async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> (StatusCode, Json<ApiResponse<SignResponse>>) {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Missing required fields".to_string())),
        );
    }

    let keypair = match keypair_verify(&payload.secret) {
        Ok(kp) => kp,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = SignResponse {
        signature: BASE64.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: payload.message,
    };

    (StatusCode::OK, Json(ApiResponse::success(response)))
}

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> (StatusCode, Json<ApiResponse<VerifyResponse>>) {
    let pubkey = match pubkey_verify(&payload.pubkey) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    let signature_bytes = match BASE64.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid signature encoding".to_string())),
            );
        }
    };

    if signature_bytes.len() != 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "Invalid signature length, must be 64 bytes".to_string(),
            )),
        );
    }

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Invalid signature format".to_string())),
            );
        }
    };

    let message_bytes = payload.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);

    let response = VerifyResponse {
        valid,
        message: payload.message,
        // FIX: Corrected field name from 'pubKey' to 'pub_key' to match models.rs
        pub_key: payload.pubkey,
    };

    (StatusCode::OK, Json(ApiResponse::success(response)))
}

async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionResponse>>) {
    let from = match pubkey_verify(&payload.from) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    let to = match pubkey_verify(&payload.to) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    if from == to {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "'from' and 'to' addresses cannot be the same".to_string(),
            )),
        );
    }

    if payload.lamports == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Lamports must be > 0".to_string())),
        );
    }

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    (
        StatusCode::OK,
        Json(ApiResponse::success(instruction_to_response(instruction))),
    )
}

async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionResponse>>) {
    let owner = match pubkey_verify(&payload.owner) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    let mint = match pubkey_verify(&payload.mint) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    let destination_user_address = match pubkey_verify(&payload.destination) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::error(e))),
    };

    if owner == destination_user_address {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "'owner' and 'destination' addresses cannot be the same".to_string(),
            )),
        );
    }

    if payload.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Amount must be > 0".to_string())),
        );
    }

    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let destination_ata = spl_associated_token_account::get_associated_token_address(
        &destination_user_address,
        &mint,
    );

    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        payload.amount,
    ) {
        Ok(instr) => instr,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            );
        }
    };

    (
        StatusCode::OK,
        Json(ApiResponse::success(instruction_to_response(instruction))),
    )
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

    let port = "8080";
    let addr = format!("0.0.0.0:{}", port);

    println!("Server up at {}, let's go!", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
