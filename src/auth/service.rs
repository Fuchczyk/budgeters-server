use std::sync::Arc;

use axum::{response::IntoResponse, Extension, Json};
use serde::Deserialize;
use sqlx::{query, PgPool, Row};

use super::{Hasher, Permissions};

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

pub enum AuthError {
    DatabaseError(String),
    InvalidUsername,
}

pub async fn check_permissions(
    username: &str,
    database: &PgPool,
) -> Result<Permissions, AuthError> {
    let query_stmt = include_str!("../../postgres/auth/check_permissions.sql");

    let query_prepared = query(query_stmt).bind(username);

    match query_prepared.fetch_optional(database).await {
        Err(error) => Err(AuthError::DatabaseError(error.to_string())),
        Ok(result) => {
            if let Some(row) = result {
                let permissions: String = row.get("permissions");
                Ok(permissions
                    .parse()
                    .expect("Unable to parse permissions from database - critical error."))
            } else {
                Err(AuthError::InvalidUsername)
            }
        }
    }
}

fn register(
    signup_form: Json<LoginForm>,
    database: Extension<Arc<PgPool>>,
    hasher: Extension<Arc<Hasher>>,
) -> impl IntoResponse {
}
