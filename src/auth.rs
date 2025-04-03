use std::str;

use base64::{prelude::BASE64_STANDARD, Engine};
use oneshot;

use axum::{
    extract::{Query, State},
    Json,
};

use serde::{Deserialize, Serialize};

use crate::app_state::AppState;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    aud: String,
    acc: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub refresh_token: String,
    pub auth_token: String,
    pub full_name: String,
    pub email: String,
    pub picture: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct AuthParams {
    code: String,
}

#[derive(Deserialize, Debug)]
struct AuthCode {
    auth_code: String,
    // error: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct UserInfo {
    id: i32,
    first_name: String,
    last_name: String,
    email: String,
    picture: Option<String>,
    refresh_token: Option<String>,
    account_ulid: Option<String>,
}

pub async fn auth_handler(
    State(state): State<AppState>,
    Query(params): Query<AuthParams>,
    // Json(_): axum::extract::Json<()>, // Dummy JSON extractor to match the handler signature
) -> Json<AuthResponse> {
    let (tx, rx) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let result = {
            let auth_code = serde_json::from_slice::<AuthCode>(
                &BASE64_STANDARD
                    .decode(&params.code)
                    .expect("Failed to decode base64"),
            )
            .expect("Failed to parse JSON from decoded auth code");

            let db = state.env.d1("HEDYLOGOS_DB").unwrap();

            let statement = db.prepare(
                "SELECT * FROM users WHERE auth_code = ? AND auth_code_expires_at > ? LIMIT 1",
            );

            let result = statement
                .bind(&[
                    auth_code.auth_code.into(),
                    chrono::Utc::now().to_string().into(),
                ])
                .unwrap()
                .all()
                .await
                .unwrap();

            let users = result.results::<UserInfo>().unwrap();

            if let Some(user) = users.first() {
                let user = user.clone();

                let statement =
                    db.prepare("UPDATE users SET auth_code_verified_at = ? WHERE id = ?");

                let _result = statement
                    .bind(&[chrono::Utc::now().to_string().into(), user.id.into()])
                    .unwrap()
                    .run()
                    .await;

                let jwt_secret = state
                    .env
                    .secret("JWT_SECRET")
                    .expect("Failed to retrieve JWT_SECRET from environment")
                    .to_string();

                let auth_token = jsonwebtoken::encode(
                    &jsonwebtoken::Header::default(),
                    &Claims {
                        sub: user.id.to_string(),
                        aud: "hedylogos".to_string(),
                        acc: user.account_ulid.unwrap_or_default(),
                        exp: chrono::Utc::now()
                            .checked_add_signed(chrono::Duration::seconds(3600))
                            .expect("valid timestamp")
                            .timestamp() as usize,
                    },
                    &jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_ref()),
                );

                // let auth_token: Result<String, Error> = Ok("".to_owned());

                AuthResponse {
                    refresh_token: user.refresh_token.unwrap_or_default(),
                    auth_token: auth_token.unwrap_or_else(|_| "".to_string()),
                    full_name: format!("{} {}", user.first_name, user.last_name),
                    email: user.email,
                    picture: user.picture.unwrap_or_default(),
                    error: None,
                }
            } else {
                // User not found, return error
                AuthResponse {
                    refresh_token: "".to_string(),
                    auth_token: "".to_string(),
                    full_name: "".to_string(),
                    email: "".to_string(),
                    picture: "".to_string(),
                    error: Some("User not found".to_string()),
                }
            }
        };
        tx.send(result).unwrap();
    });

    Json(rx.await.unwrap())
}
