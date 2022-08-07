mod auth;
mod database;
mod session;

use std::{str::FromStr, sync::Arc};

use axum::{
    extract::Path, http::StatusCode, middleware::from_fn, response::IntoResponse, Extension,
    Router, Server,
};
use chrono::Duration;
use dotenv::dotenv;
use lazy_static::lazy_static;
use sqlx::{PgPool, Pool, Postgres};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

lazy_static! {
    static ref SESSION_TIME: Duration = Duration::hours(2);
    static ref PEPPER: Vec<u8> = vec![1, 2, 3];
}
// TODO: Middleware to ensure that every request has session cookie.
#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "budgeters_server=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let hasher = auth::Hasher::new(&*PEPPER.as_slice());
    let database_connection = Arc::new(database::initialize_database_pool().await);

    let server_router = Router::new()
        .layer(from_fn(session::ensure_session))
        .layer(Extension(database_connection))
        .layer(Extension(Arc::new(hasher)))
        .layer(tower_http::trace::TraceLayer::new_for_http());
    let server_address = std::env::var("BG_SERVERADDRESS").unwrap();

    let server_outcome = Server::bind(
        &server_address
            .parse()
            .expect("Unable to parse BG_SERVERADDRESS env variable."),
    )
    .serve(server_router.into_make_service())
    .await;

    println!("SERVER OUTCOME IS {server_outcome:?}");
}
