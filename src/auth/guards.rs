use std::sync::Arc;

use axum::{
    extract::{FromRequest, RequestParts},
    http::StatusCode,
    Json,
};
use sqlx::PgPool;

use crate::session;

use super::Permissions;
use async_trait::async_trait;
use serde_json::{json, Value};

macro_rules! authorization_guards {
    ($struct_name:ident, $rights:ident; $($t:tt)*) => {
        authorization_guards!($struct_name, $rights);
        authorization_guards!($($t)*);
    };

    ($struct_name:ident, $rights:ident) => {
        pub struct $struct_name {}

        #[async_trait]
        impl<B> FromRequest<B> for $struct_name
        where
            B: Send,
        {
            type Rejection = (StatusCode, Json<Value>);

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let session_info = match req.extract::<session::SessionInfo>().await {
                    Ok(session_info) => session_info,
                    Err(error) => {
                        tracing::warn!("Error while retriving session info from request. Error = [{}]", error.1);

                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "Unable to extract session info."}))
                        ));
                    }
                };
                let database = match req.extensions().get::<Arc<PgPool>>() {
                    Some(db) => db,
                    None => {
                        tracing::error!("Unable to get database in authorization_guard of [{}].", Permissions::$rights);

                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "Unable to establish connection with database."})),
                        ));
                    }
                };

            match session_info.read_permissions(database).await {
                    Ok(None) => {
                        Err((
                            StatusCode::FORBIDDEN,
                            Json(json!({
                                "your_level": "None",
                                "required_level": Permissions::$rights.to_string()
                            }))
                        ))
                    }
                    Ok(Some(permissions)) => {
                        if permissions < Permissions::$rights {
                         Err((
                            StatusCode::FORBIDDEN,
                            Json(json!({
                                "your_level": permissions.to_string(),
                                "required_level": Permissions::$rights.to_string()
                            }))
                        ))

                        } else {
                            Ok($struct_name {})
                        }
                    }
                    Err(error) => {
                        tracing::error!("Error occured while guarding access level. Error = [{}]", error);

                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({
                                "error": error.to_string()
                            }))
                        ))
                    }
                }
            }
        }
    };

    () => {}
}

authorization_guards! {
    UserGuard, User;
    AdminGuard, Admin;
    ModeratorGuard, Moderator;
}
