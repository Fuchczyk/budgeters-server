use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, Params,
};

fn pepper_generator() -> Vec<u8> {
    vec![12, 61, 178, 12, 3, 87, 12, 225, 17, 143, 162, 8]
}

const MEMORY_BLOCKS: u32 = 15360; // 5MB
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;
const HASH_LENGTH: usize = 64;

pub type PasswordHash = [u8; HASH_LENGTH];

#[derive(Clone)]
pub struct Hasher<'a> {
    argon2_alg: Argon2<'a>,
}

impl<'a> Hasher<'a> {
    pub fn new(key: &'a [u8]) -> Self {
        let params = Params::new(MEMORY_BLOCKS, ITERATIONS, PARALLELISM, Some(HASH_LENGTH))
            .expect("Unable to create password hasher.");

        Hasher {
            argon2_alg: Argon2::new_with_secret(
                key,
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                params,
            )
            .expect("Unable to create Argon2 structure with provided secret."),
        }
    }

    fn hash_password(&self, password: &[u8], salt: &[u8]) -> PasswordHash {
        let mut result: PasswordHash = [0; HASH_LENGTH];

        self.argon2_alg
            .hash_password_into(password, salt, &mut result)
            .expect("Unable to perform password hashing!");

        result
    }
    pub fn process_password(&self, password: &[u8]) -> (PasswordHash, SaltString) {
        let salt = SaltString::generate(&mut OsRng);
        let result = self.hash_password(password, salt.as_bytes());

        (result, salt)
    }

    pub fn password_check(&self, password: &[u8], salt: &[u8], hash: &PasswordHash) -> bool {
        let calculated_hash = self.hash_password(password, salt);

        calculated_hash.eq(hash)
    }
}
