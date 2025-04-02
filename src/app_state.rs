use std::sync::Arc;

use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, EndpointNotSet, EndpointSet, RedirectUrl,
    TokenUrl,
};
use worker::Env;

pub type Oauth2ClientWithEndpoints =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

#[derive(Clone)]
pub struct AppState {
    pub oauth_client: Arc<Oauth2ClientWithEndpoints>,
    pub env: Env,
    pub app_url: String,
}

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

impl AppState {
    pub fn new(env: Env) -> Self {
        // --- Get Configuration from Worker Environment ---
        let client_id = env
            .var("GOOGLE_CLIENT_ID")
            .expect("Failed to retrieve GOOGLE_CLIENT_ID from environment")
            .to_string();

        let client_secret = env
            .secret("GOOGLE_CLIENT_SECRET")
            .expect("Failed to retrieve GOOGLE_CLIENT_SECRET from environment")
            .to_string();

        let redirect_uri = env
            .var("REDIRECT_URI")
            .expect("Failed to retrieve REDIRECT_URI from environment")
            .to_string();

        let oauth_client = BasicClient::new(ClientId::new(client_id))
            .set_client_secret(ClientSecret::new(client_secret))
            .set_auth_uri(
                AuthUrl::new(GOOGLE_AUTH_URL.to_string()).expect("Failed to parse GOOGLE_AUTH_URL"),
            )
            .set_token_uri(
                TokenUrl::new(GOOGLE_TOKEN_URL.to_string())
                    .expect("Failed to parse GOOGLE_TOKEN_URL"),
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri).expect("Failed to parse REDIRECT_URI"),
            );

        let app_url = env
            .var("APP_REDIRECT_URI")
            .expect("Failed to retrieve APP_REDIRECT_URI from environment")
            .to_string();

        Self {
            oauth_client: Arc::new(oauth_client),
            env,
            app_url,
        }
    }
}
