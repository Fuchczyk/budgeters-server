mod credentials;
mod guards;
mod service;

pub use credentials::Hasher;
pub use service::check_permissions;
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
            &Permissions::User => "user",
            &Permissions::Admin => "admin",
            &Permissions::Moderator => "moderator",
        };

        write!(f, "{result_string}")
    }
}

impl FromStr for Permissions {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Permissions::User),
            "admin" => Ok(Permissions::Admin),
            "moderator" => Ok(Permissions::Moderator),
            _ => Err("Given string does not represent application's permission."),
        }
    }
}

mod tests {
    use super::*;

    #[test]
    fn permissions_hierarchy() {
        assert!(Permissions::User < Permissions::Moderator);
        assert!(Permissions::Moderator < Permissions::Admin);
    }
}
