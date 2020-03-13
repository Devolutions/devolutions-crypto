use base64;
use devolutions_crypto::{utils::derive_key, Argon2Parameters, DcDataBlob};

use std::convert::TryFrom as _;

#[test]
fn test_derive_key_default() {
    let password = b"testpassword";
    let salt = b"";

    let derived_password = derive_key(password, salt, 10000, 32);
    assert_eq!(
        derived_password,
        base64::decode("ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=").unwrap()
    );
}

#[test]
fn test_derive_key_iterations() {
    let password = b"testPa$$";
    let salt = b"";

    let derived_password = derive_key(password, salt, 100, 32);
    assert_eq!(
        derived_password,
        base64::decode("ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=").unwrap()
    );
}

#[test]
fn test_derive_key_salt() {
    let password = b"testPa$$";
    let salt = base64::decode("tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA=").unwrap();

    let derived_password = derive_key(password, &salt, 100, 32);
    assert_eq!(
        derived_password,
        base64::decode("ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=").unwrap()
    );
}

#[test]
fn test_symmetric_decrypt_v1() {
    let key = base64::decode("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=").unwrap();
    let ciphertext = base64::decode("DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==").unwrap();

    let ciphertext = DcDataBlob::try_from(ciphertext.as_slice()).unwrap();
    let result = ciphertext.decrypt(&key).unwrap();

    assert_eq!(result, b"test Ciph3rtext~");
}

#[test]
fn test_symmetric_decrypt_v2() {
    let key = base64::decode("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=").unwrap();
    let ciphertext = base64::decode(
        "DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=",
    )
    .unwrap();

    let ciphertext = DcDataBlob::try_from(ciphertext.as_slice()).unwrap();
    let result = ciphertext.decrypt(&key).unwrap();

    assert_eq!(result, b"test Ciph3rtext~2");
}

#[test]
fn test_derive_keypair() {
    let params = Argon2Parameters::try_from(
        base64::decode("AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ==")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let (private_key, public_key) = DcDataBlob::derive_keypair(b"password", &params).unwrap();

    let private_key: Vec<u8> = private_key.into();
    let public_key: Vec<u8> = public_key.into();

    assert_eq!(
        private_key,
        base64::decode("DQwBAAEAAQAAwQ3oJvU6bq2iZlJwAzvbmqJczNrFoeWPeIyJP9SSbQ==").unwrap()
    );
    assert_eq!(
        public_key,
        base64::decode("DQwBAAIAAQBwfx5kOF4iEHXF+jyYRjfQYZnGCy0SQMHeRZCxRVvmCg==").unwrap()
    );
}

#[test]
fn test_asymmetric_decrypt_v2() {
    let private_key = DcDataBlob::try_from(
        base64::decode("DQwBAAEAAQAAwQ3oJvU6bq2iZlJwAzvbmqJczNrFoeWPeIyJP9SSbQ==")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let ciphertext = DcDataBlob::try_from(base64::decode("DQwCAAIAAgCIG9L2MTiumytn7H/p5I3aGVdhV3WUL4i8nIeMWIJ1YRbNQ6lEiQDAyfYhbs6gg1cD7+5Ft2Q5cm7ArsGfiFYWnscm1y7a8tAGfjFFTonzrg==").unwrap().as_slice()).unwrap();

    let result = ciphertext.decrypt_asymmetric(&private_key).unwrap();

    assert_eq!(result, b"testdata");
}

#[test]
fn test_password_hashing_v1() {
    let hash1 = DcDataBlob::try_from(base64::decode("DQwDAAAAAQAQJwAAXCzLFoyeZhFSDYBAPiIWhCk04aoP/lalOoCl7D+skIY/i+3WT7dn6L8WvnfEq6flCd7i+IcKb3GEK4rCpzhDlw==").unwrap().as_slice()).unwrap();
    let hash2 = DcDataBlob::try_from(base64::decode("DQwDAAAAAQAKAAAAmH1BBckBJYDD0xfiwkAk1xwKgw8a57YQT0Igm+Faa9LFamTeEJgqn/qHc2R/8XEyK2iLPkVy+IErdGLLtLKJ2g==").unwrap().as_slice()).unwrap();

    assert!(hash1.verify_password(b"password1").unwrap());
    assert!(hash2.verify_password(b"password1").unwrap());
}
