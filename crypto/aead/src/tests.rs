use crate::{decrypt, encrypt, get_encryption_key};

#[test]
fn encrypts_and_decrypts() {
    let password = "test123";
    let salt = "salt1235";
    let message = "hello world";

    let key = get_encryption_key(password, salt).unwrap();
    let mut cipher_text = encrypt(message.as_bytes().to_vec(), &key).unwrap();
    let decrypted = decrypt(&mut cipher_text, &key).unwrap();

    assert_eq!(decrypted, message.as_bytes());
}
