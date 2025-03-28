use axum::{routing::get, Router};

mod google_auth;
use google_auth::{google_callback_handler, google_login_handler};

mod app_state;
use app_state::AppState;

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

    let mut app = Router::new()
        .route("/", get(root))
        .route("/auth/google/login", get(google_login_handler))
        .route("/auth/google/callback", get(google_callback_handler))
        .with_state(shared_state);

    Ok(app.call(req).await?)
}

pub async fn root() -> &'static str {
    "おはよう!"
}
