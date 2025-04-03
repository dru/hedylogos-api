use axum::{routing::get, Router};

mod google_auth;
use google_auth::{google_callback_handler, google_login_handler};

mod app_state;
use app_state::AppState;

mod auth;
use auth::auth_handler;

mod jwt_extractor;

use jwt_extractor::Claims;
use reqwest::Method;
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::{event, Context, Env, HttpRequest, Result};

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();

    let shared_state = AppState::new(env);

    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any);

    let mut app = Router::new()
        .route("/", get(root))
        .route("/auth/google/login", get(google_login_handler))
        .route("/auth/google/callback", get(google_callback_handler))
        .route("/auth/", get(auth_handler))
        .layer(cors)
        .with_state(shared_state);

    Ok(app.call(req).await?)
}

pub async fn root(claims: Claims, // Dummy extractor to match the handler signature
) -> String {
    format!(
        "おはよう! Your token is valid. {} {} {}",
        claims.sub, claims.acc, claims.exp
    )
}
