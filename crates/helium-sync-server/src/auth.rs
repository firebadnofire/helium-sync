use axum::{
    extract::{Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::Response,
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::api::{ApiError, AppState};

pub fn token_digest(token: &SecretString) -> [u8; 32] {
    Sha256::digest(token.expose_secret().as_bytes()).into()
}

pub async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let presented = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "a bearer token is required",
            )
        })?;
    let presented_digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    if !bool::from(presented_digest.ct_eq(&state.token_digest)) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "authentication_rejected",
            "the bearer token was rejected",
        ));
    }
    Ok(next.run(request).await)
}
