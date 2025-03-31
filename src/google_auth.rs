use oneshot;

use axum::{
    extract::{Query, State},
    Json,
};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};

use rand::{distr::Alphanumeric, Rng};
use wasm_bindgen_futures::wasm_bindgen::JsValue;

use serde::{Deserialize, Serialize};

use worker::console_error;

use crate::app_state::AppState;

#[derive(Debug, Serialize)]

pub struct AuthResponse {
    pub redirect_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// --- /auth/google/login Handler ---
pub async fn google_login_handler(
    State(state): State<AppState>,
    // Json(_): axum::extract::Json<()>, // Dummy JSON extractor to match the handler signature
) -> Json<AuthResponse> {
    let (tx, rx) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let result = {
            // your code

            let kv = state.env.kv("HEDYLOGOS_KV").unwrap();

            // Generate PKCE challenge and verifier
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

            // Generate CSRF token
            let (auth_url, csrf_token) = state
                .oauth_client
                .authorize_url(CsrfToken::new_random)
                // Add desired scopes
                .add_scope(Scope::new("openid".to_string()))
                .add_scope(Scope::new("email".to_string()))
                .add_scope(Scope::new("profile".to_string()))
                // Set PKCE challenge
                .set_pkce_challenge(pkce_challenge)
                .url();

            // Store the PKCE verifier and CSRF token state in KV
            // Key: CSRF token string, Value: PKCE verifier secret string
            // Use a short TTL (e.g., 5 minutes = 300 seconds)
            let _ = kv
                .put(&csrf_token.secret().to_string(), pkce_verifier.secret())
                .unwrap()
                .expiration_ttl(300) // 5 minutes
                .execute()
                .await
                .unwrap();

            // console_log!("Redirecting to: {}", auth_url);
            // Redirect the user to Google's authorization page
            AuthResponse {
                redirect_url: auth_url.to_string(),
                error: None,
            }
        };
        tx.send(result).unwrap();
    });
    Json(rx.await.unwrap())
}

// --- Query parameters received on callback ---
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String, // This is the CSRF token
}

#[derive(Debug, Serialize)]
pub struct CallbackResponse {
    auth_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// --- /auth/google/callback Handler ---
#[axum::debug_handler]
pub async fn google_callback_handler(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
    // Json(_): axum::extract::Json<()>, // Dummy JSON extractor to match the handler signature
) -> Json<CallbackResponse> {
    let (tx, rx) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let result = {
            let kv = state.env.kv("HEDYLOGOS_KV").unwrap();

            // Retrieve the PKCE verifier using the state (CSRF token) as the key
            let pkce_verifier_secret = match kv.get(&params.state).text().await.unwrap() {
                Some(secret) => secret,
                None => {
                    console_error!("Invalid state or expired CSRF token.");
                    // return Ok(Json("Invalid state or expired CSRF token.".to_string()));
                    return ();
                }
            };

            // Clean up the used state from KV
            kv.delete(&params.state).await.unwrap();

            // Reconstruct the PKCE verifier
            let pkce_verifier = PkceCodeVerifier::new(pkce_verifier_secret);

            let http_client = reqwest::Client::builder()
                // Following redirects opens the client up to SSRF vulnerabilities.
                // .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Client should build");

            // Now we can trade it for an access token.
            let token_response = state
                .oauth_client
                .exchange_code(AuthorizationCode::new(params.code))
                // Set the PKCE code verifier.
                .set_pkce_verifier(pkce_verifier)
                .request_async(&http_client)
                .await;

            match token_response {
                Ok(token_result) => {
                    // Use the access token to fetch user info from Google API.

                    let user_info_response = reqwest::Client::new()
                        .get("https://www.googleapis.com/oauth2/v3/userinfo")
                        .bearer_auth(token_result.access_token().secret())
                        .send()
                        .await
                        .expect("Failed to fetch user info");

                    let user_info: serde_json::Value = user_info_response
                        .json()
                        .await
                        .expect("Failed to parse user info response");

                    let user_info_value =
                        |key: &str| JsValue::from(user_info[key].as_str().unwrap_or_default());

                    let refresh_token = rand::rng()
                        .sample_iter(&Alphanumeric)
                        .take(32)
                        .map(char::from)
                        .collect::<String>();

                    let auth_code = rand::rng()
                        .sample_iter(&Alphanumeric)
                        .take(32)
                        .map(char::from)
                        .collect::<String>();

                    let access_token = token_result.access_token().secret();
                    let provider = "google".to_string();

                    // Find or create a user record in database.
                    let db = state
                        .env
                        .d1("HEDYLOGOS_DB")
                        .expect("Failed to get DB binding");

                    let statement = db.prepare(
                        r#"
                            INSERT INTO users 
                            (email, first_name, last_name, picture, auth_code, auth_code_expires_at, refresh_token, access_token, provider) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(email, provider) 
                            DO UPDATE SET 
                            auth_code = excluded.auth_code,
                            refresh_token = excluded.refresh_token,
                            access_token = excluded.access_token,
                            first_name = excluded.first_name,
                            last_name = excluded.last_name,
                            picture = excluded.picture,
                            updated_at = CURRENT_TIMESTAMP;
                        "#,
                    );

                    let result = statement
                        .bind(&[
                            user_info_value("email"),
                            user_info_value("given_name"),
                            user_info_value("family_name"),
                            user_info_value("picture"),
                            auth_code.clone().into(),
                            // Expires in 2 min
                            (chrono::Utc::now() + chrono::Duration::minutes(2))
                                .to_string()
                                .into(),
                            refresh_token.into(),
                            access_token.into(),
                            provider.into(),
                        ])
                        .unwrap()
                        .run()
                        .await;

                    match result {
                        Ok(_) => CallbackResponse {
                            auth_code: auth_code.clone(),
                            error: None,
                        },

                        Err(e) => CallbackResponse {
                            auth_code: "".to_string(),
                            error: Some(format!("Database error: {}", e)),
                        },
                    }
                }
                Err(e) => CallbackResponse {
                    auth_code: "".to_string(),
                    error: Some(format!("Token error: {}", e)),
                },
            }
        };
        tx.send(result).unwrap();
    });
    Json(rx.await.unwrap())
}
