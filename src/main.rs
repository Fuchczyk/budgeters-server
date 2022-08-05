mod auth;
mod database;
mod session;

use std::{str::FromStr, sync::Arc};

use axum::{extract::Path, http::StatusCode, response::IntoResponse, Extension, Router, Server};
use chrono::Duration;
use dotenv::dotenv;
use lazy_static::lazy_static;
use sqlx::{PgPool, Pool, Postgres};

lazy_static! {
    static ref SESSION_TIME: Duration = Duration::hours(2);
    static ref PEPPER: Vec<u8> = vec![1, 2, 3];
}
// TODO: Middleware to ensure that every request has session cookie.
#[tokio::main]
async fn main() {
    dotenv().ok();

    let hasher = auth::Hasher::new(&*PEPPER.as_slice());
    let database_connection = database::initialize_database_pool().await;

    let server_router = Router::new()
        .route("/get", axum::routing::get(test))
        .route("/check/:uuid", axum::routing::get(test_uuid))
        .layer(Extension(Arc::new(database_connection)))
        .layer(Extension(Arc::new(hasher)));

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

async fn test(database: Extension<Pool<Postgres>>) -> impl IntoResponse {
    let uuid = session::fresh_session(&database.0).await;

    (StatusCode::OK, format!("Got uuid = {uuid:?}"))
}

async fn test_uuid(database: Extension<Pool<Postgres>>, uuid: Path<String>) -> impl IntoResponse {
    let status =
        session::check_session(uuid::Uuid::from_str(uuid.as_str()).unwrap(), &database.0).await;

    (StatusCode::OK, format!("Got stuct = {status:?}"))
}
