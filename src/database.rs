use sqlx::postgres::{PgConnectOptions, PgPool};

fn read_variable(var_name: &str) -> String {
    std::env::var(var_name).unwrap_or_else(|_| panic!("Unable to find {} env variable!", var_name))
}

pub async fn initialize_database_pool() -> PgPool {
    let database_host = read_variable("BG_HOST");
    let database_port = read_variable("BG_PORT");
    let database_user = read_variable("BG_USER");
    let database_password = read_variable("BG_PASSWORD");
    let database_name = read_variable("BG_DATABASE");

    let connect_options = PgConnectOptions::new()
        .database(&database_name)
        .host(&database_host)
        .username(&database_user)
        .password(&database_password)
        .port(
            database_port
                .parse()
                .expect("Unable to parse BG_PORT env variable."),
        )
        .ssl_mode(sqlx::postgres::PgSslMode::Prefer);

    let pool = PgPool::connect_with(connect_options)
        .await
        .expect("Unable to establish connection with PostgreSQL database.");

    pool
}
