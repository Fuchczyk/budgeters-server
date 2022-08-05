mod management;

use crate::auth::Permissions;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{query, query_as, FromRow, PgPool};
use uuid::Uuid;

#[derive(FromRow, Debug)]
pub struct SessionInfo {
    session_id: Uuid,
    expiration_date: NaiveDateTime,
    username: Option<String>,
}

#[derive(Debug)]
pub enum SessionError {
    UuidNotFound,
    SessionExpired,
    DatabaseError(String),
}

impl SessionInfo {
    async fn try_insert(&self, database: &PgPool) -> Result<(), sqlx::Error> {
        let query_stmt = include_str!("../../postgres/session/insert_session.sql");
        let query_prepared = sqlx::query(query_stmt)
            .bind(self.session_id)
            .bind(self.expiration_date)
            .bind(&self.username);

        match query_prepared.execute(database).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn try_read(uuid: Uuid, database: &PgPool) -> Result<Option<Self>, sqlx::Error> {
        let query_stmt = include_str!("../../postgres/session/read_session.sql");
        let query_prepared = query_as(&query_stmt).bind(&uuid);

        Ok(query_prepared.fetch_optional(database).await?)
    }

    fn new(uuid: Uuid) -> SessionInfo {
        let expiration_date = chrono::Utc::now().naive_utc() + *crate::SESSION_TIME;

        SessionInfo {
            session_id: uuid,
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
}

pub async fn fresh_session(database: &PgPool) -> Result<Uuid, String> {
    loop {
        let uuid = Uuid::new_v4();

        let fresh_info = SessionInfo::new(uuid);
        let a = update_session(uuid.clone(), database, "at").await;
        match fresh_info.try_insert(database).await {
            Ok(()) => return Ok(uuid),
            Err(sqlx::Error::Database(e)) if e.constraint() == Some("session_id") => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub async fn check_session(uuid: Uuid, database: &PgPool) -> Result<SessionInfo, SessionError> {
    match SessionInfo::try_read(uuid, database).await {
        Ok(result) => match result {
            Some(s_id) => Ok(s_id),
            None => Err(SessionError::UuidNotFound),
        },
        Err(e) => Err(SessionError::DatabaseError(e.to_string())),
    }
}

pub async fn update_session(
    uuid: Uuid,
    database: &PgPool,
    username: &str,
) -> Result<(), SessionError> {
    let update_stmt = include_str!("../../postgres/session/update_session.sql");
    let expiration_date = chrono::Utc::now().naive_utc() + *crate::SESSION_TIME;

    let query_prepared = query(&update_stmt)
        .bind(username)
        .bind(&expiration_date)
        .bind(uuid);

    match query_prepared.execute(database).await {
        Err(e) => Err(SessionError::DatabaseError(e.to_string())),
        Ok(result) => {
            if result.rows_affected() == 1 {
                Ok(())
            } else {
                Err(SessionError::UuidNotFound)
            }
        }
    }
}
