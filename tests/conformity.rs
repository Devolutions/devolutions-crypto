use base64::{engine::general_purpose, Engine as _};
use devolutions_crypto::{
    ciphertext::Ciphertext,
    key::{PrivateKey, SecretKey},
    password_hash::PasswordHash,
    utils::{derive_key_argon2, derive_key_pbkdf2},
    Argon2Parameters, KdfEncryptedData,
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
fn test_derive_key_argon2_struct() {
    use devolutions_crypto::key_derivation::Argon2;
    let params = Argon2Parameters::try_from(
        general_purpose::STANDARD
            .decode("AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ==")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let argon2 = Argon2::with_params(params.clone());
    let (key, _derivation_params) = argon2.derive(b"password").unwrap();
    assert_eq!(
        key.as_bytes(),
        &general_purpose::STANDARD
            .decode("AcEN6Cb1Om6tomZScAM725qiXMzaxaHlj3iMiT/Ukq0=")
            .unwrap()[..]
    );
}

#[test]
fn test_derive_key_default() {
    let password = b"testpassword";
    let salt = b"";

    let derived_password = derive_key_pbkdf2(password, salt, 600000, 32);
    assert_eq!(
        derived_password,
        general_purpose::STANDARD
            .decode("wdU+cxAOpTFddVhTQlKQTSzmVjZqPAXVx1cRrAqTGek=")
            .unwrap()
    );
}

#[test]
fn test_derive_key_pbkdf2_struct_default() {
    use devolutions_crypto::key_derivation::Pbkdf2;
    let password = b"testpassword";
    let salt = b"";
    let pbkdf2 = Pbkdf2::with_params(600000);
    let (key, _params) = pbkdf2.derive_with_salt(password, salt).unwrap();
    assert_eq!(
        key.as_bytes(),
        &general_purpose::STANDARD
            .decode("wdU+cxAOpTFddVhTQlKQTSzmVjZqPAXVx1cRrAqTGek=")
            .unwrap()[..]
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
fn test_derive_key_pbkdf2_struct_iterations() {
    use devolutions_crypto::key_derivation::Pbkdf2;
    let password = b"testPa$$";
    let salt = b"";
    let pbkdf2 = Pbkdf2::with_params(100);
    let (key, _params) = pbkdf2.derive_with_salt(password, salt).unwrap();
    assert_eq!(
        key.as_bytes(),
        &general_purpose::STANDARD
            .decode("ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=")
            .unwrap()[..]
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
fn test_derive_key_pbkdf2_struct_salt() {
    use devolutions_crypto::key_derivation::Pbkdf2;
    let password = b"testPa$$";
    let salt = general_purpose::STANDARD
        .decode("tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA=")
        .unwrap();
    let pbkdf2 = Pbkdf2::with_params(100);
    let (key, _params) = pbkdf2.derive_with_salt(password, &salt).unwrap();
    assert_eq!(
        key.as_bytes(),
        &general_purpose::STANDARD
            .decode("ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=")
            .unwrap()[..]
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
fn test_password_hashing_v2() {
    // Argon2id hash for "password1" with memory=65536 KiB, iterations=3, salt="conformity_salt!"
    // Generated with: Argon2Parameters { memory: 65536, iterations: 3, salt: "conformity_salt!" }
    let hash = PasswordHash::try_from(
        general_purpose::STANDARD
            .decode("DQwDAAAAAgA2AAAADQwIAAAAAgABAAAAIAAAAAEAAAAAAAEAAwAAAAITAAAAABAAAABjb25mb3JtaXR5X3NhbHQh0qPjrO8QR1p1wS+cThwEhBO+ouwFraKqpo0TVJLosMM=")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    assert!(hash.verify_password(b"password1"));
    assert!(!hash.verify_password(b"password2"));
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

#[test]
fn test_derive_decrypt_with_password_v1() {
    let data = general_purpose::STANDARD
        .decode("DQwJAAAAAQA2AAAAQgAAAA0MCAAAAAIAAQAAACAAAAABAAAAABAAAAIAAAACEwAAAAAQAAAAToyZHBBdwMfQ/nSt8fAG2g0MAgABAAIAOy6I4UgmX2jX+ji691rHdSKa5r4X1ItGiT6BszvL1eagyovyr/0DPMM2eIOmctQzuiQHgQ2BXrULGQ==")
        .unwrap();

    let blob = KdfEncryptedData::try_from(data.as_slice()).unwrap();
    let result = blob.decrypt_with_password(b"DevoCrypto!").unwrap();

    assert_eq!(result, b"Derive and Encrypt");
}

#[test]
fn test_symmetric_decrypt_with_secret_key_v2() {
    // SecretKey wrapping the known key ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=
    // Header: sig=0x0D0C, DataType::Key=1, KeySubtype::Secret=4, KeyVersion::V1=1
    let secret_key = SecretKey::try_from(
        general_purpose::STANDARD
            .decode("DQwBAAQAAQCjMlUSZ7j7l7/g0bcL5GXboZBsZYCoZzRA9fz/XG9oUw==")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let ciphertext = Ciphertext::try_from(
        general_purpose::STANDARD
            .decode("DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let result = ciphertext.decrypt_with_secret_key(&secret_key).unwrap();

    assert_eq!(result, b"test Ciph3rtext~2");
}

#[test]
fn test_online_ciphertext_decrypt_symmetric_v1() {
    // Cross-version STREAM known-answer vector (key "Key123", chunk size 1000): locks the
    // STREAM-LE31 wire format so a crate bump that silently changes it is caught here.
    use devolutions_crypto::online_ciphertext::OnlineCiphertextHeader;

    let key = b"Key123";
    let tag_size = 16usize;

    let header_bytes = general_purpose::STANDARD
        .decode("DQwHAAEAAADoAwAAOU63lZRBVkAapzo92zfg/KZy6/o=")
        .unwrap();

    let ciphertext = general_purpose::STANDARD
        .decode("OF1pXe1lexpcY4iBF8Vq5CGtRhK9QyvYar8U5fLHxZpnzEeUDAW7LbxoOUhjQqRW+VMnACB61r/FLNMUz0dVxcuvV1bZj1RxO3x/4xCybMMRc394UyG08KdI3+FAveGbjBG3r2G49RtqAS+IJb31VAIbuEmxkiEG0KgQlEKp9ZXevJGZwlG5VT9RIiKYtJ1FB1/crTSuANtZhSfVvO/iGc7TnTI+Fd23/GHY8/aFAeL9AAnG6qp+X/N4l0fP1klZFlP/0A+Q9xshz4fZ8N0RHjSrEU2YbV79LnLIwBd1U0NPArVUmiJd2Nblmc/6dfH9wB6i0VQYzk5yz4UQZ/n/9aF2h9jkMjpUVPyDwq+Eelzqb6ZJUNn1bpontHqe7PBCBj5GHTBt8FjOI92ZIpHte9OKk3i/Ni1HmqGdjVmne1oP023x9IX9mX4+i8XeCwn+RQ9xmoYRgdK2UzSs9KSyA9dOhQyH5rXF6gL7QtSgDsPa6uVuuk5NnrNyTNanTTUkc1W612WzcKPRpSOH+IeIGPUuEMju5X0qsDPRziNg5P78z8QDNlGYe4r+d7uYTiQsFhqsl7/GgyXFIJbEKtpUuhpk82nSZAyhF1jRv4pdU5hI9rg0FOo9E0S/iE5UkICUfHRpLw9X2PaJIzyIuIHoTJ/BITt1FZIk19T+IuC3ITSc/ziP3ptRjR9EK5hSyVXdWEn+N5ac/umeHsf5/nY+H3FN7Z1EzNG5Jglb5iOECy3NWted0jggPJcJnDsQCWuig2AY7dU8dA9IpmDFMT8bVjfBwW0oqgFdhd1Tc9+eyO36imr0PZOjCLYLppbTB8ddb/6D5WtD98P0xwXxIqFLT0KaT6CiskN2QetVBq+MDKqf1Sq4YnGuiRrE8UBVmOAfekZfsZVFClXpoLPVPfCTa+l5WHad3TMuEDFjYiU/wX9jjPXV8xAheCpN+qZb9V6w0quF6hhH22+3e4oUENLd2sJVrotcAh919StKwmq+mYz4b890z76gw5YTdk82i83ZHj9R+x4769bMlATxARC999dxwwqB3EGh8B4O25O5r9SQkLMtgqqmE5fpgYWrPlqitV1zlyMvEZi284B4uIM5xgTJW0jaJmigEVFJ08D4/DGP3mPfNfz+G7bFc/FaNAFyIZjd2Y64208cbPJPCCFMqLtlcMIaKQhnTNs8rielVAxWH63V/FOpw+9Zj8uB6m1EQLAFbgIqmgRdVelk6/lKI8XsI0D+Oe5H+X8GwM5Ts9s5+xAzYSkBQs5k8Gx6FH8M7KBhZIyV8TB5PPTANKfMqt9+mx8BeUTYPGtbdEqsHosuis6+hegM57F5OJ0hL/hGhSXJZbzFYsiiI0OLsYVuexDZ4UoB7cI6cTpIDcL7a0xS1U/qKErr6MFZz6mpJ2x0a1E14Dk1/d6uCOAYkYawwxl3UQpHli7WOk1XU3iS8NJzshixpWb9k4Ac1+bEu6uXjeSXAU24rbMtm6ck9en7y/LcSCuqlH7W22obKcuIGHRwgLSIMvthB/SA+g9BDEJVIEjdfOQeaqJv4WENT+797OWp9888X7MSLf95Ecn+w4dtk7zGgZA65y565QbEVKPDrvE76ed1u0gDY4YOPVWJNMzlE+RBowPSYZz0SiKIQwsqXpuQMWl1Id0+WMLzMtFyBKmAxpAeCEuAUiBiuYjv5Bfv44slCYB2BP3lEcqtZtC5uVf7BiXI+5gFyja3KmzKNjD6uLxXmyg5bjH3113qkRg5SPxFMAzgSXxERu3gru85qSiDExbbV5Ppv2OVJZwqkKbWZgcdv16R3PMbUzzLleIj09p4G3U04U7B4QrIdtR1lb3BsPVYHA3fX12U5f3/sIJSnZ9Nl2YnjX5JpW9achzKq0THDn8xTQhWbUnXyTRt5xXr9ENf+wegFAKYpxoafSDcZnd4veDjaXYFkQJPgHpDib7LjzVRa47j76UWgoEKdYlwJHcsPi6I3ag0vQCFeVdQfdrinwgpr2A5ZgNrc9Cav9tuGiM29sBIEtW80MTT0IjljAzYzsSaFD3pzxvR4phCA53XMphRgFsbT9tTaLiNPfIqFNXCPZ0tBIh3Ur/qHg/fIsUZj6fmiL582Y4ltkEG6VPpXH4mBJXA4GSe50P9IHOWvNZgOUT18IXEFrkSYVZweh9yPvzsvI7tbI36xLYyYiS7kn47kgh75m+8XttDj3wYpKLDkSk832Z3cPsxFXtJqMrDyIftSsVBPoNaBEcv2FSZuuFwQ7PqJ+Rn73f1bFbV2R6iYupYZ0GxH6N8pXk+LkfJM7w=")
        .unwrap();

    let expected_plaintext = general_purpose::STANDARD
        .decode("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gTnVsbGFtIHF1YW0gbnVuYywgcGxhY2VyYXQgbWF4aW11cyBmYWNpbGlzaXMgZGlnbmlzc2ltLCB0aW5jaWR1bnQgaW4gdHVycGlzLiBEdWlzIHRlbXBvciBtYWduYSBldSBjb252YWxsaXMgbWF0dGlzLiBOdWxsYW0gcmhvbmN1cyBsYWN1cyBub24gbmliaCBtb2xlc3RpZSBzb2RhbGVzLiBJbiBub24gdHJpc3RpcXVlIG51bmMuIE51bGxhIGlkIGdyYXZpZGEgbnVuYy4gRG9uZWMgZWdlc3RhcyBtaSBlZ2V0IHRlbGx1cyBlZmZpY2l0dXIsIG1vbGxpcyBsb2JvcnRpcyB1cm5hIHRyaXN0aXF1ZS4gVml2YW11cyBzZWQgdGVsbHVzIHZpdGFlIG1ldHVzIG1hdHRpcyBsYWNpbmlhLiBWZXN0aWJ1bHVtIGRhcGlidXMgZXN0IGV1IHB1bHZpbmFyIGxhb3JlZXQuIEV0aWFtIGNvbW1vZG8gZXJvcyBhdCBmYWNpbGlzaXMgbW9sbGlzLiBDdXJhYml0dXIgcnV0cnVtIHRpbmNpZHVudCBzZW0sIHZpdGFlIHBsYWNlcmF0IG51bmMgbGFjaW5pYSBuZWMuIE9yY2kgdmFyaXVzIG5hdG9xdWUgcGVuYXRpYnVzIGV0IG1hZ25pcyBkaXMgcGFydHVyaWVudCBtb250ZXMsIG5hc2NldHVyIHJpZGljdWx1cyBtdXMuIFBoYXNlbGx1cyBjdXJzdXMgYXVndWUgdXQgbmlzbCB0ZW1wdXMgbGFjaW5pYS4gCk51bGxhIHZpdGFlIGZlcm1lbnR1bSBlc3QsIGV0IHZlaGljdWxhIG1hdXJpcy4gSW50ZXJkdW0gZXQgbWFsZXN1YWRhIGZhbWVzIGFjIGFudGUgaXBzdW0gcHJpbWlzIGluIGZhdWNpYnVzLiBQaGFzZWxsdXMgc2l0IGFtZXQgbWFnbmEgcGVsbGVudGVzcXVlLCBtYXhpbXVzIGp1c3RvIHZpdGFlLCBtYWxlc3VhZGEgYW50ZS4gVmVzdGlidWx1bSBhbnRlIGlwc3VtIHByaW1pcyBpbiBmYXVjaWJ1cyBvcmNpIGx1Y3R1cyBldCB1bHRyaWNlcyBwb3N1ZXJlIGN1YmlsaWEgY3VyYWU7IFN1c3BlbmRpc3NlIHRlbXB1cyBkb2xvciBldSBhdWd1ZSByaG9uY3VzIHBoYXJldHJhLiBEb25lYyB2aXRhZSBuaXNpIHBlbGxlbnRlc3F1ZSwgY29udmFsbGlzIG9kaW8gYXQsIGludGVyZHVtIGF1Z3VlLiBQZWxsZW50ZXNxdWUgYXQgcHVydXMgYSBuaWJoIGxhY2luaWEgdWxsYW1jb3JwZXIgYWMgYSBudWxsYS4gQWVuZWFuIG5pYmggbGlndWxhLCBoZW5kcmVyaXQgaW4gbHVjdHVzIGV0LCBzb2RhbGVzIG5vbiB0dXJwaXMuIE51bGxhIGZhY2lsaXNpLiBOdWxsYSBsYW9yZWV0IG1hc3NhIGZlbGlzLCBhIGRpY3R1bSBsaWd1bGEgYmxhbmRpdCB1dC4gClNlZCBzb2RhbGVzIHJpc3VzIGp1c3RvLCB1dCBmZXJtZW50dW0gc2FwaWVuIGRpY3R1bSBzZWQuIFNlZCB1bHRyaWNlcyB2ZWxpdCBldCBmZWxpcyBmZXJtZW50dW0gaW50ZXJkdW0uIFZlc3RpYnVsdW0gY29uc2VjdGV0dXIgbGFvcmVldCBpcHN1bS4gUGVsbGVudGVzcXVlIGhhYml0YW50IG1vcmJpIHRyaXN0aXF1ZSBzZW5lY3R1cyBldCBuZXR1cyBldCBtYWxlc3VhZGEgZmFtZXMgYWMgdHVycGlzIGVnZXN0YXMuIENyYXMgaW4gZXggc3VzY2lwaXQsIGFjY3Vtc2FuIHB1cnVzIHZpdGFlLCByaG9uY3VzIGVsaXQuIE1hZWNlbmFzIHF1aXMgc2FwaWVuIG5vbiBxdWFtIGFjY3Vtc2FuIHZlaGljdWxhIHNlZCB2aXRhZSBwdXJ1cy4gUHJvaW4gY29uc2VxdWF0IGlwc3VtIGluIGxhY3VzIGxvYm9ydGlzIHRlbXB1cy4gRG9uZWMgYWMgYWxpcXVldCBtYXNzYS4g")
        .unwrap();

    let header = OnlineCiphertextHeader::try_from(header_bytes.as_slice()).unwrap();
    let chunk_with_tag = header.get_chunk_size() as usize + tag_size;

    let mut decryptor = header.into_decryptor(key, b"").unwrap();

    let mut result = Vec::new();
    let mut offset = 0;

    // Every chunk but the last is a full `chunk_size + tag` block.
    while ciphertext.len() - offset > chunk_with_tag {
        result.extend_from_slice(
            &decryptor
                .decrypt_next_chunk(&ciphertext[offset..offset + chunk_with_tag], b"")
                .unwrap(),
        );
        offset += chunk_with_tag;
    }

    result.extend_from_slice(
        &decryptor
            .decrypt_last_chunk(&ciphertext[offset..], b"")
            .unwrap(),
    );

    assert_eq!(result, expected_plaintext);
}
