DROP SCHEMA IF EXISTS sessions CASCADE;
DROP SCHEMA IF EXISTS credentials CASCADE;

CREATE SCHEMA IF NOT EXISTS credentials;

CREATE TABLE credentials.session_info (
    session_id VARCHAR UNIQUE NOT NULL,
    expiration_date TIMESTAMP NOT NULL,
    username VARCHAR
);

CREATE TABLE credentials.auth_info (
  username VARCHAR UNIQUE NOT NULL,
  salt BYTEA NOT NULL,
  password_hash BYTEA NOT NULL,
  permissions VARCHAR NOT NULL
)
