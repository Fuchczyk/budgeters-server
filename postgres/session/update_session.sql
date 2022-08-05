UPDATE credential.session_info
SET username=$1, expiration_date=$2
WHERE session_id=$3;
