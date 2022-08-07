SELECT permissions
FROM credentials.auth_info
WHERE username = $1;
