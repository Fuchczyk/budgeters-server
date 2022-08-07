use axum::{
    headers::{Cookie as HeaderCookie, HeaderMapExt},
    http::{
        header::{COOKIE, SET_COOKIE},
        HeaderValue, Request, StatusCode,
    },
    middleware::Next,
    response::Response,
};
use sqlx::PgPool;

use crate::session::verify_session_id;

use cookie::{Cookie, CookieBuilder};
use std::sync::Arc;

use super::SessionId;

pub(super) const SESSION_COOKIE_NAME: &str = "budgeters_session";

fn create_session_cookie(session_id: SessionId) -> Cookie<'static> {
    CookieBuilder::new(SESSION_COOKIE_NAME, session_id)
        .secure(true)
        // TODO: Expiration parameter.
        .http_only(true)
        .finish()
}

async fn create_session<B>(
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, (StatusCode, String)> {
    let database = match req.extensions().get::<Arc<PgPool>>() {
        Some(db) => db,
        None => {
            tracing::error!("Unable to get database handler from Request.");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to establish connection to database.".into(),
            ));
        }
    };

    match super::fresh_session(database).await {
        Ok(id) => {
            let cookie = create_session_cookie(id);
            req.headers_mut().insert(
                COOKIE,
                HeaderValue::from_str(&cookie.stripped().to_string()).unwrap(),
            );

            let mut response = next.run(req).await;
            response.headers_mut().insert(
                SET_COOKIE,
                HeaderValue::from_str(&cookie.to_string()).unwrap(),
            );

            Ok(response)
        }
        Err(error) => {
            tracing::error!("Error giving fresh session_id. Error=[{}]", error);

            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to give new session id.".into(),
            ))
        }
    }
}

pub async fn ensure_session<B>(
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, (StatusCode, String)> {
    let cookies = match req.headers().typed_get::<HeaderCookie>() {
        Some(cookies) => cookies,
        None => {
            return create_session(req, next).await;
            tracing::debug!("Unable to get cookies from response.");
            return Err((
                StatusCode::BAD_REQUEST,
                "Unable to read cookies from request.".into(),
            ));
        }
    };

    let database = match req.extensions().get::<Arc<PgPool>>() {
        Some(db) => db,
        None => {
            tracing::error!("Unable to get database handler from Request.");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to establish connection to database.".into(),
            ));
        }
    };

    if let Some(session_id) = cookies.get(SESSION_COOKIE_NAME) {
        match verify_session_id(session_id, database).await {
            Ok(true) => Ok(next.run(req).await),
            Ok(false) => create_session(req, next).await,
            Err(error) => {
                tracing::error!(
                    "Error while veryfing session_id. SessionId=[{}], Error=[{}]",
                    session_id,
                    error
                );

                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unable to verify session id.".into(),
                ))
            }
        }
    } else {
        create_session(req, next).await
    }
}
