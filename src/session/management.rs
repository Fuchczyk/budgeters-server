use axum::{
    extract::{FromRequest, RequestParts},
    http::{response, StatusCode},
    response::IntoResponse,
    Extension,
};
use axum_extra::extract::PrivateCookieJar;
use sqlx::PgPool;

use crate::auth::Permissions;
use async_trait::async_trait;

const SESSION_COOKIE_NAME: &str = "budgeters_session";

pub struct Session {
    username: Option<String>,
    permissions: Option<Permissions>,
}

impl Session {
    fn new(username: Option<String>, permissions: Option<Permissions>) -> Self {
        Self {
            username,
            permissions,
        }
    }
}

#[async_trait]
impl<R> FromRequest<R> for Session
where
    R: Send,
{
    type Rejection = (StatusCode, Option<PrivateCookieJar>, String);

    async fn from_request(req: &mut RequestParts<R>) -> Result<Self, Self::Rejection> {
        let db_try = req.extract::<Extension<PgPool>>().await;
        let database = match db_try {
            Ok(db) => db,
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "Unable to extract database from RequestParts.".into(),
                ));
            }
        };

        let cookie_try = req.extract::<PrivateCookieJar>().await;
        let mut priv_cookies = match cookie_try {
            Ok(cj) => cj,
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "Unable to extract private cookies from RequestParts.".into(),
                ));
            }
        };

        match priv_cookies.get(SESSION_COOKIE_NAME) {
            None => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "Session cookie should always be present.".into(),
                ));
            }
            Some(cookie) => {
                let uuid: uuid::Uuid = match cookie.value().parse() {
                    Ok(uuid) => uuid,
                    Err(_) => {
                        priv_cookies = priv_cookies.remove(cookie);
                        return Err((
                            StatusCode::BAD_REQUEST,
                            Some(priv_cookies),
                            "Session cookie's value is invalid.".into(),
                        ));
                    }
                };

                let session_info = match super::check_session(uuid, &database.0).await {
                    Err(super::SessionError::UuidNotFound) => {
                        priv_cookies = priv_cookies.remove(cookie);
                        return Err((
                            StatusCode::BAD_REQUEST,
                            Some(priv_cookies),
                            "Session cookie's value cannot be found in database.".into(),
                        ));
                    }
                    Err(_) => {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            None,
                            "Unable to communicate with session database.".into(),
                        ));
                    }
                    Ok(session_info) => session_info,
                };

                if let Some(username) = session_info.username() {
                    match crate::auth::check_permissions(username, &database.0).await {
                        Ok(perm) => Ok(Session::new(Some(username.into()), Some(perm))),
                        Err(crate::auth::AuthError::InvalidUsername) => {
                            priv_cookies = priv_cookies.remove(cookie);
                            return Err((
                                StatusCode::BAD_REQUEST,
                                Some(priv_cookies),
                                "Username connected to session cookie cannot be found in database."
                                    .into(),
                            ));
                        }
                        Err(crate::auth::AuthError::DatabaseError(error)) => {
                            // TODO! LOG ERROR
                            return Err((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                None,
                                "Internal database server error.".into(),
                            ));
                        }
                    }
                } else {
                    Ok(Session::new(None, None))
                }
            }
        }
    }
}
