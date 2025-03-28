use oneshot;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    Json,
};

use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};

use serde::Deserialize;

use worker::{console_error, console_log};

use crate::app_state::AppState;

// --- /auth/google/login Handler ---
pub async fn google_login_handler(
    State(state): State<AppState>,
    // Json(_): axum::extract::Json<()>, // Dummy JSON extractor to match the handler signature
) -> axum::response::Result<impl IntoResponse> {
    let (tx, rx) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let result = {
            // your code

            let kv = state.env.kv(&state.kv_binding_name).unwrap();

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
                .execute()
                .await
                .unwrap();

            console_log!("Redirecting to: {}", auth_url);
            // Redirect the user to Google's authorization page
            Ok(Redirect::to(auth_url.as_str()))
        };
        tx.send(result).unwrap();
    });
    rx.await.unwrap()
}

// --- Query parameters received on callback ---
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String, // This is the CSRF token
}

// --- /auth/google/callback Handler ---
#[axum::debug_handler]
pub async fn google_callback_handler(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
    // Json(_): axum::extract::Json<()>, // Dummy JSON extractor to match the handler signature
) -> axum::response::Result<Json<String>> {
    let (tx, rx) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let result = {
            console_log!("Callback received. State: {}", params.state);
            let kv = state.env.kv(&state.kv_binding_name).unwrap();

            // Retrieve the PKCE verifier using the state (CSRF token) as the key
            let pkce_verifier_secret = match kv.get(&params.state).text().await.unwrap() {
                Some(secret) => secret,
                None => {
                    console_error!("Invalid state or expired CSRF token.");
                    // In a real app, return a user-friendly error page/message
                    // return Ok(Json("Invalid state or expired CSRF token.".to_string()));
                    return ();
                }
            };

            // Clean up the used state from KV
            kv.delete(&params.state).await.unwrap();

            // Reconstruct the PKCE verifier
            let pkce_verifier = PkceCodeVerifier::new(pkce_verifier_secret);

            // Exchange the authorization code for an access token
            // let token_response = state
            //     .oauth_client
            //     .set_exchange_code(AuthorizationCode::new(params.code))
            //     .set_pkce_verifier(pkce_verifier)
            //     .request_async(async_http_client)
            //     .await;

            let http_client = reqwest::Client::builder()
                // Following redirects opens the client up to SSRF vulnerabilities.
                // .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Client should build");

            // Now you can trade it for an access token.
            let token_response = state
                .oauth_client
                .exchange_code(AuthorizationCode::new(params.code))
                // Set the PKCE code verifier.
                .set_pkce_verifier(pkce_verifier)
                .request_async(&http_client)
                .await;

            match token_response {
                Ok(token_result) => {
                    // --- IMPORTANT ---
                    // Successfully obtained the token!
                    // In a real application, you would now:
                    // 1. Use the `token_result.access_token()` to fetch user info from Google API.
                    // 2. Find or create a user record in your database.
                    // 3. Generate your *own* session token/cookie.
                    // 4. Store your session token securely (e.g., in KV associated with user ID).
                    // 5. Set the session cookie in the user's browser and redirect them to a logged-in page.

                    // For this *minimal* example, just confirm success.
                    //             console_log!(
                    //     "OAuth token exchange successful. Access Token: [REDACTED], Expires in: {:?}, Scopes: {:?}",
                    //     token_result.expires_in(),
                    //     token_result.scopes()
                    // );

                    // You might store the access_token or refresh_token in KV here,
                    // perhaps keyed by a new session ID you generate and set as a cookie.
                    // Example (conceptual):
                    // let session_id = generate_secure_session_id();
                    // kv.put(&format!("session:{}", session_id), token_result.access_token().secret())?.execute().await?;
                    // let cookie = format!("session_id={}; HttpOnly; Secure; Path=/", session_id);
                    // return Response::redirect("/dashboard")?.with_header("Set-Cookie", cookie);

                    Ok(Json(format!(
                        "Login Successful! (Token retrieved, scope) {:?}",
                        token_result.scopes()
                    )))
                }
                Err(_) => Ok(Json("Error!".to_string())),
            }
        };
        tx.send(result).unwrap();
    });
    rx.await.unwrap()
}
