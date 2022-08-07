use std::sync::Arc;

use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{query, PgPool, Row};

use super::{Hasher, Permissions, Unauthorized};

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub enum AuthError {
    DatabaseError(String),
    InvalidUsername,
    UsernameTaken,
}

async fn insert_user(
    database: &PgPool,
    username: &str,
    password_hash: &[u8],
    salt: &[u8],
    permissions: Permissions,
) -> Result<(), AuthError> {
    let insert_stmt = include_str!("../../postgres/auth/register_user.sql");

    let query_prepared = query(&insert_stmt)
        .bind(username)
        .bind(salt)
        .bind(password_hash)
        .bind(permissions.to_string());

    match query_prepared.execute(database).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.as_database_error().map_or_else(
            || AuthError::DatabaseError(e.to_string()),
            |db_error| {
                db_error.code().map_or_else(
                    || AuthError::DatabaseError(e.to_string()),
                    |code| {
                        if code == "23505" {
                            AuthError::UsernameTaken
                        } else {
                            AuthError::DatabaseError(e.to_string())
                        }
                    },
                )
            },
        )),
    }
}

pub async fn register(
    signup_form: Json<LoginForm>,
    database: Extension<Arc<PgPool>>,
    hasher: Extension<Arc<Hasher<'_>>>,
    _guard: Unauthorized,
) -> (StatusCode, Json<Value>) {
    let (password_hash, user_salt) = hasher.process_password(signup_form.password.as_bytes());

    match insert_user(
        database.as_ref(),
        &signup_form.username,
        &password_hash,
        user_salt.as_bytes(),
        Permissions::User,
    )
    .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({
                "error": "None"
            })),
        ),
        Err(AuthError::UsernameTaken) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "UsernameTaken"
            })),
        ),
        Err(AuthError::DatabaseError(error)) => {
            tracing::error!("Error occured while signup process. Error = [{}]", error);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "DatabaseError"
                })),
            )
        }
        _ => {
            unimplemented!("Other error are not possible.");
        }
    }
}
