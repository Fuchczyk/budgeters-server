INSERT INTO credentials.auth_info (username, salt, password_hash, permissions)
VALUES ($1, $2, $3, $4);
