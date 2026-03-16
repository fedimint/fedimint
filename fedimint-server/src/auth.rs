use fedimint_core::module::ApiAuth;
use subtle::ConstantTimeEq as _;

const BCRYPT_COST: u32 = 12;

fn is_bcrypt_hash(s: &str) -> bool {
    s.starts_with("$2b$") || s.starts_with("$2a$") || s.starts_with("$2y$")
}

pub fn hash_password(plaintext: &str) -> String {
    bcrypt::hash(plaintext, BCRYPT_COST).expect("Failed to hash password with bcrypt")
}

pub fn verify_password(plaintext: &str, stored: &str) -> bool {
    if is_bcrypt_hash(stored) {
        bcrypt::verify(plaintext, stored).unwrap_or(false)
    } else {
        plaintext.as_bytes().ct_eq(stored.as_bytes()).into()
    }
}

pub fn verify_api_auth(request_auth: Option<&ApiAuth>, stored_auth: &ApiAuth) -> bool {
    match request_auth {
        Some(request) => verify_password(&request.0, &stored_auth.0),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "test_password_123";
        let hashed = hash_password(password);

        assert!(
            is_bcrypt_hash(&hashed),
            "Hashed password should be in bcrypt format"
        );
        assert!(
            verify_password(password, &hashed),
            "Correct password should verify"
        );
        assert!(
            !verify_password("wrong_password", &hashed),
            "Wrong password should not verify"
        );
    }

    #[test]
    fn test_legacy_plaintext_verify() {
        let password = "my_plaintext_secret";

        assert!(
            verify_password(password, password),
            "Plaintext should match itself"
        );
        assert!(
            !verify_password("wrong", password),
            "Wrong plaintext should not match"
        );
    }

    #[test]
    fn test_verify_api_auth_bcrypt() {
        let plaintext = "guardian_password";
        let stored = ApiAuth(hash_password(plaintext));
        let request = ApiAuth(plaintext.to_string());

        assert!(verify_api_auth(Some(&request), &stored));
        assert!(!verify_api_auth(None, &stored));
        assert!(!verify_api_auth(
            Some(&ApiAuth("wrong".to_string())),
            &stored
        ));
    }

    #[test]
    fn test_verify_api_auth_legacy_plaintext() {
        let stored = ApiAuth("legacy_pass".to_string());
        let request = ApiAuth("legacy_pass".to_string());

        assert!(verify_api_auth(Some(&request), &stored));
        assert!(!verify_api_auth(
            Some(&ApiAuth("wrong".to_string())),
            &stored
        ));
    }
}
