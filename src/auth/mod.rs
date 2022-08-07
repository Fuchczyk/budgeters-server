mod credentials;
mod guards;
mod service;

use axum::Router;
pub use credentials::Hasher;
pub use guards::{AdminGuard, ModeratorGuard, Unauthorized, UserGuard};
pub use service::AuthError;

use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Permissions {
    User,
    Moderator,
    Admin,
}

impl Display for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let result_string = match &self {
            &Permissions::User => "User",
            &Permissions::Admin => "Admin",
            &Permissions::Moderator => "Moderator",
        };

        write!(f, "{result_string}")
    }
}

impl FromStr for Permissions {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "User" => Ok(Permissions::User),
            "Admin" => Ok(Permissions::Admin),
            "Moderator" => Ok(Permissions::Moderator),
            _ => Err("Given string does not represent application's permission."),
        }
    }
}

pub fn routes() -> Router {
    Router::new().route("/signup", axum::routing::post(service::register))
}

mod tests {
    use super::Permissions;

    #[test]
    fn permissions_hierarchy() {
        assert!(Permissions::User < Permissions::Moderator);
        assert!(Permissions::Moderator < Permissions::Admin);
    }
}
