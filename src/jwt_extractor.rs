use axum::{http::request::Parts, RequestPartsExt};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;

// Define your claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,  // Expiration time
    pub aud: String, // Audience
    pub acc: String,
}

// Extractor for validating JWT token

impl axum::extract::FromRequestParts<AppState> for Claims {
    type Rejection = String;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header: TypedHeader<Authorization<Bearer>> =
            parts.extract().await.map_err(|_| "Missing Header")?;

        // Decode and validate the token
        let secret = state
            .env
            .secret("JWT_SECRET")
            .expect("Failed to retrieve JWT_SECRET from environment")
            .to_string();

        let decoding_key = DecodingKey::from_secret(secret.as_ref());

        let mut validation = Validation::default();
        validation.set_audience(&["hedylogos".to_string()]);

        let token_data: TokenData<Claims> =
            match decode(auth_header.token(), &decoding_key, &validation) {
                Ok(data) => data,
                Err(e) => {
                    return Err("Invalid token".to_string());
                }
            };

        // Check the expiration time
        if token_data.claims.exp < chrono::Utc::now().timestamp() as usize {
            return Err("Token expired".to_string());
        }

        // Return the claims if valid
        return Ok(token_data.claims);
    }
}
