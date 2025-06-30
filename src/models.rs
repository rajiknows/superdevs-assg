use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct keypair_response {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstructionResponse {
    pub program_id: String,
    pub accounts: Vec<AccountMetaResponse>,
    pub instruction_data: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountMetaResponse {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub valid: bool,
    pub message: String,
    pub pub_key: String,
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

#[derive(Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

#[derive(Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}
#[derive(Deserialize)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}
#[derive(Deserialize)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}
