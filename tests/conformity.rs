use base64::{engine::general_purpose, Engine as _};
use devolutions_crypto::{
    ciphertext::Ciphertext,
    key::PrivateKey,
    password_hash::PasswordHash,
    utils::{derive_key_argon2, derive_key_pbkdf2},
    Argon2Parameters,
};

use std::convert::TryFrom as _;

#[test]
fn test_derive_key_argon2() {
    let params = Argon2Parameters::try_from(
        general_purpose::STANDARD
            .decode("AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ==")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let key = derive_key_argon2(b"password", &params).unwrap();

    assert_eq!(
        key,
        general_purpose::STANDARD
            .decode("AcEN6Cb1Om6tomZScAM725qiXMzaxaHlj3iMiT/Ukq0=")
            .unwrap()
    );
}

#[test]
fn test_derive_key_default() {
    let password = b"testpassword";
    let salt = b"";

    let derived_password = derive_key_pbkdf2(password, salt, 10000, 32);
    assert_eq!(
        derived_password,
        general_purpose::STANDARD
            .decode("ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=")
            .unwrap()
    );
}

#[test]
fn test_derive_key_iterations() {
    let password = b"testPa$$";
    let salt = b"";

    let derived_password = derive_key_pbkdf2(password, salt, 100, 32);
    assert_eq!(
        derived_password,
        general_purpose::STANDARD
            .decode("ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=")
            .unwrap()
    );
}

#[test]
fn test_derive_key_salt() {
    let password = b"testPa$$";
    let salt = general_purpose::STANDARD
        .decode("tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA=")
        .unwrap();

    let derived_password = derive_key_pbkdf2(password, &salt, 100, 32);
    assert_eq!(
        derived_password,
        general_purpose::STANDARD
            .decode("ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=")
            .unwrap()
    );
}

#[test]
fn test_symmetric_decrypt_v1() {
    let key = general_purpose::STANDARD
        .decode("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
        .unwrap();
    let ciphertext = general_purpose::STANDARD.decode("DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==").unwrap();

    let ciphertext = Ciphertext::try_from(ciphertext.as_slice()).unwrap();
    let result = ciphertext.decrypt(&key).unwrap();

    assert_eq!(result, b"test Ciph3rtext~");
}

#[test]
fn test_symmetric_decrypt_aad_v1() {
    let key = general_purpose::STANDARD
        .decode("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
        .unwrap();
    let aad = b"this is some public data";

    let ciphertext = general_purpose::STANDARD.decode("DQwCAAEAAQCeKfbTqYjfVCEPEiAJjiypBstPmZz0AnpliZKoR+WXTKdj2f/4ops0++dDBVZ+XdyE1KfqxViWVc9djy/HSCcPR4nDehtNI69heGCIFudXfQ==").unwrap();

    let ciphertext = Ciphertext::try_from(ciphertext.as_slice()).unwrap();
    let result = ciphertext.decrypt_with_aad(&key, aad).unwrap();

    assert_eq!(result, b"test Ciph3rtext~");
}

#[test]
fn test_symmetric_decrypt_v2() {
    let key = general_purpose::STANDARD
        .decode("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
        .unwrap();
    let ciphertext = general_purpose::STANDARD.decode(
        "DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=",
    )
    .unwrap();

    let ciphertext = Ciphertext::try_from(ciphertext.as_slice()).unwrap();
    let result = ciphertext.decrypt(&key).unwrap();

    assert_eq!(result, b"test Ciph3rtext~2");
}

#[test]
fn test_symmetric_decrypt_aad_v2() {
    let key = general_purpose::STANDARD
        .decode("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
        .unwrap();
    let aad = b"this is some public data";

    let ciphertext = general_purpose::STANDARD.decode("DQwCAAEAAgA9bh989dao0Pvaz1NpJTI5m7M4br2qVjZtFwXXoXZOlkCjtqU/uif4pbNCcpEodzeP4YG1QvfKVQ==").unwrap();

    let ciphertext = Ciphertext::try_from(ciphertext.as_slice()).unwrap();
    let result = ciphertext.decrypt_with_aad(&key, aad).unwrap();

    assert_eq!(result, b"test Ciph3rtext~");
}

#[test]
fn test_asymmetric_decrypt_v2() {
    let private_key = PrivateKey::try_from(
        general_purpose::STANDARD
            .decode("DQwBAAEAAQAAwQ3oJvU6bq2iZlJwAzvbmqJczNrFoeWPeIyJP9SSbQ==")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let ciphertext = Ciphertext::try_from(general_purpose::STANDARD.decode("DQwCAAIAAgCIG9L2MTiumytn7H/p5I3aGVdhV3WUL4i8nIeMWIJ1YRbNQ6lEiQDAyfYhbs6gg1cD7+5Ft2Q5cm7ArsGfiFYWnscm1y7a8tAGfjFFTonzrg==").unwrap().as_slice()).unwrap();

    let result = ciphertext.decrypt_asymmetric(&private_key).unwrap();

    assert_eq!(result, b"testdata");
}

#[test]
fn test_asymmetric_decrypt_aad_v2() {
    let private_key = PrivateKey::try_from(
        general_purpose::STANDARD
            .decode("DQwBAAEAAQC9qf9UY1ovL/48ALGHL9SLVpVozbdjYsw0EPerUl3zYA==")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let ciphertext = Ciphertext::try_from(general_purpose::STANDARD.decode("DQwCAAIAAgB1u62xYeyppWf83QdWwbwGUt5QuiAFZr+hIiFEvMRbXiNCE3RMBNbmgQkLr/vME0BeQa+uUTXZARvJcyNXHyAE4tSdw6o/psU/kw/Z/FbsPw==").unwrap().as_slice()).unwrap();
    let aad = b"this is some public data";

    let result = ciphertext
        .decrypt_asymmetric_with_aad(&private_key, aad)
        .unwrap();

    assert_eq!(result, b"testdata");
}

#[test]
fn test_password_hashing_v1() {
    let hash1 = PasswordHash::try_from(general_purpose::STANDARD.decode("DQwDAAAAAQAQJwAAXCzLFoyeZhFSDYBAPiIWhCk04aoP/lalOoCl7D+skIY/i+3WT7dn6L8WvnfEq6flCd7i+IcKb3GEK4rCpzhDlw==").unwrap().as_slice()).unwrap();
    let hash2 = PasswordHash::try_from(general_purpose::STANDARD.decode("DQwDAAAAAQAKAAAAmH1BBckBJYDD0xfiwkAk1xwKgw8a57YQT0Igm+Faa9LFamTeEJgqn/qHc2R/8XEyK2iLPkVy+IErdGLLtLKJ2g==").unwrap().as_slice()).unwrap();

    assert!(hash1.verify_password(b"password1"));
    assert!(hash2.verify_password(b"password1"));
}

#[test]
fn test_signature_v1() {
    use devolutions_crypto::signature::Signature;
    use devolutions_crypto::signing_key::SigningPublicKey;
    use std::convert::TryInto;

    let data = b"this is a test";
    let wrong_data = b"this is wrong";

    let public_key: SigningPublicKey = (general_purpose::STANDARD
        .decode("DQwFAAIAAQDeEvwlEigK5AXoTorhmlKP6+mbiUU2rYrVQ25JQ5xang==")
        .unwrap()
        .as_slice())
    .try_into()
    .unwrap();
    let signature: Signature = (general_purpose::STANDARD.decode("DQwGAAAAAQD82uRk4sFC8vEni6pDNw/vOdN1IEDg9cAVfprWJZ/JBls9Gi61cUt5u6uBJtseNGZFT7qKLvp4NUZrAOL8FH0K").unwrap().as_slice()).try_into().unwrap();

    assert!(signature.verify(data, &public_key));
    assert!(!signature.verify(wrong_data, &public_key));
}

#[test]
fn test_utils_base64_url() {
    use devolutions_crypto::utils::{base64_decode_url, base64_encode_url};

    assert_eq!(base64_encode_url(b"Ab6/"), "QWI2Lw");
    assert_eq!(base64_encode_url(b"Ab6/75"), "QWI2Lzc1");
    assert_eq!(base64_encode_url(&[0xff, 0xff, 0xfe, 0xff]), "___-_w");

    assert_eq!(base64_decode_url("QWI2Lw").unwrap(), b"Ab6/");
    assert_eq!(base64_decode_url("QWI2Lzc1").unwrap(), b"Ab6/75");
    assert_eq!(
        base64_decode_url("___-_w").unwrap(),
        &[0xff, 0xff, 0xfe, 0xff]
    );
}

#[test]
fn test_utils_base64() {
    use devolutions_crypto::utils::{base64_decode, base64_encode};

    let data = b"Base64Test";

    let base64_data = "QmFzZTY0VGVzdA==";
    let base64_data_no_pad = "QmFzZTY0VGVzdA";

    assert_eq!(base64_decode(base64_data).unwrap(), data);
    assert_eq!(base64_decode(base64_data_no_pad).unwrap(), data);

    assert_eq!(base64_encode(data), "QmFzZTY0VGVzdA==");
}
