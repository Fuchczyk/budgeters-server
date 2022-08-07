mod management;

use std::{fmt::Display, sync::Arc};

use async_trait::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    headers::HeaderMapExt,
    http::StatusCode,
};
use chrono::NaiveDateTime;
use rand::{thread_rng, Rng};
use sqlx::{query, query_as, FromRow, PgPool, Row};

pub use management::ensure_session;

use crate::auth::Permissions;

#[derive(FromRow, Debug)]
pub struct SessionInfo {
    session_id: SessionId,
    expiration_date: NaiveDateTime,
    username: Option<String>,
}

#[derive(Debug)]
pub enum SessionError {
    SessionIdNotFound,
    SessionExpired,
    DatabaseError(String),
}

impl Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionIdNotFound => {
                write!(f, "Session id cannot be found in the database.")
            }
            Self::SessionExpired => {
                write!(f, "Session of given id has expired.")
            }
            Self::DatabaseError(error) => {
                write!(f, "DatabaseError. {error}")
            }
        }
    }
}

const SESSION_ID_BITS: usize = 256; // Must be multiple of 8.
pub type SessionId = String;
pub type SessionIdReference<'a> = &'a str;

impl SessionInfo {
    async fn try_insert(&self, database: &PgPool) -> Result<(), sqlx::Error> {
        let query_stmt = include_str!("../../postgres/session/insert_session.sql");
        let query_prepared = sqlx::query(query_stmt)
            .bind(&self.session_id)
            .bind(self.expiration_date)
            .bind(&self.username);

        match query_prepared.execute(database).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn try_read(
        session_id: SessionIdReference<'_>,
        database: &PgPool,
    ) -> Result<Option<Self>, sqlx::Error> {
        let query_stmt = include_str!("../../postgres/session/read_session.sql");
        let query_prepared = query_as(&query_stmt).bind(&session_id);

        Ok(query_prepared.fetch_optional(database).await?)
    }

    fn new(session_id: SessionId) -> SessionInfo {
        let expiration_date = chrono::Utc::now().naive_utc() + *crate::SESSION_TIME;

        SessionInfo {
            session_id,
            expiration_date: expiration_date,
            username: None,
        }
    }

    pub fn username(&self) -> Option<&str> {
        match &self.username {
            None => None,
            Some(username) => Some(&username),
        }
    }

    pub async fn read_permissions(
        &self,
        database: &PgPool,
    ) -> Result<Option<Permissions>, sqlx::Error> {
        if self.username.is_none() {
            return Ok(None);
        }

        let read_stmt = include_str!("../../postgres/session/read_permissions.sql");

        let query_prepared = query(read_stmt).bind(self.username.as_ref().unwrap());
        let query_result = query_prepared.fetch_optional(database).await?;

        match query_result {
            None => {
                tracing::error!(
                    "Cannot find row with username = [{}] in order to read permissions.",
                    self.username.as_ref().unwrap()
                );

                Err(sqlx::Error::Protocol(
                    "Tables in database has conflicting data.".into(),
                ))
            }
            Some(row) => match row.try_get::<Option<String>, _>("permissions") {
                Ok(Some(permissions)) => Ok(Some(permissions.parse().unwrap())),
                Ok(None) => Ok(None),
                Err(error) => {
                    tracing::error!(
                        "Unable to extract permissions from database row. Error = [{}]",
                        error
                    );

                    Err(error)
                }
            },
        }
    }
}

fn generate_session_id() -> String {
    const BYTES: usize = SESSION_ID_BITS / 8;

    let array: [u8; BYTES] = thread_rng().gen();
    base64::encode(array)
}

pub async fn fresh_session(database: &PgPool) -> Result<SessionId, String> {
    loop {
        let session_id = generate_session_id();

        let fresh_info = SessionInfo::new(session_id.clone());

        match fresh_info.try_insert(database).await {
            Ok(()) => return Ok(session_id),
            Err(sqlx::Error::Database(e)) if e.constraint() == Some("session_id") => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub async fn check_session(
    session_id: SessionIdReference<'_>,
    database: &PgPool,
) -> Result<SessionInfo, SessionError> {
    match SessionInfo::try_read(session_id, database).await {
        Ok(result) => match result {
            Some(s_id) => Ok(s_id),
            None => Err(SessionError::SessionIdNotFound),
        },
        Err(e) => Err(SessionError::DatabaseError(e.to_string())),
    }
}

pub async fn update_session(
    session_id: SessionId,
    database: &PgPool,
    username: &str,
) -> Result<(), SessionError> {
    let update_stmt = include_str!("../../postgres/session/update_session.sql");
    let expiration_date = chrono::Utc::now().naive_utc() + *crate::SESSION_TIME;

    let query_prepared = query(&update_stmt)
        .bind(username)
        .bind(&expiration_date)
        .bind(&session_id);

    match query_prepared.execute(database).await {
        Err(e) => Err(SessionError::DatabaseError(e.to_string())),
        Ok(result) => {
            if result.rows_affected() == 1 {
                Ok(())
            } else {
                Err(SessionError::SessionIdNotFound)
            }
        }
    }
}

async fn remove_session(
    session_id: SessionIdReference<'_>,
    database: &PgPool,
) -> Result<(), SessionError> {
    let remove_stmt = include_str!("../../postgres/session/remove_session.sql");

    let query_prepared = query(&remove_stmt).bind(session_id);

    match query_prepared.execute(database).await {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::error!(
                "Error occured while removing session [{}] from database. Error = [{}]",
                session_id,
                e
            );

            Err(SessionError::DatabaseError(e.to_string()))
        }
    }
}

pub async fn verify_session_id(
    session_id: SessionIdReference<'_>,
    database: &PgPool,
) -> Result<bool, SessionError> {
    match SessionInfo::try_read(session_id, database).await {
        Ok(result) => {
            if let Some(info) = result {
                let current_date = chrono::Utc::now().naive_utc();

                if info.expiration_date <= current_date {
                    remove_session(session_id, database).await;
                    Ok(false)
                } else {
                    Ok(true)
                }
            } else {
                Ok(false)
            }
        }
        Err(error) => {
            tracing::error!(
                "Error occured while veryfing session_id = [{}]. Error = [{}].",
                session_id,
                error
            );
            Err(SessionError::DatabaseError(error.to_string()))
        }
    }
}

#[async_trait]
impl<B> FromRequest<B> for SessionInfo
where
    B: Send,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let cookies = match req.headers().typed_get::<axum::headers::Cookie>() {
            Some(cookies) => cookies,
            None => {
                tracing::warn!(
                    "No cookies was found - possible problem with ensure_session middleware."
                );

                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "No cookies were found".into(),
                ));
            }
        };

        let database = match req.extensions().get::<Arc<PgPool>>() {
            Some(db) => db,
            None => {
                tracing::error!("Unable to get database from extensions in SessionInfo extractor.");

                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Cannot establish connection with database.".into(),
                ));
            }
        };

        let session_id = match cookies.get(management::SESSION_COOKIE_NAME) {
            Some(value) => value,
            None => {
                tracing::error!("Unable to get session cookie. Possible problem with ensure_session middleware.");

                return Err((
                    StatusCode::BAD_REQUEST,
                    "No session cookie was found".into(),
                ));
            }
        };

        match SessionInfo::try_read(&session_id, database).await {
            Ok(Some(info)) => Ok(info),
            Ok(None) => {
                tracing::warn!(
                    "Session cookie cannot be found in database. SessionId = [{}]",
                    session_id
                );

                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Cannot find user session in database. Try again.".into(),
                ))
            }
            Err(error) => {
                tracing::error!("Database error has occured in SessionInfo extractor. Session_id = [{}]. Error = [{}]", session_id, error);
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error has occured".into(),
                ))
            }
        }
    }
}
