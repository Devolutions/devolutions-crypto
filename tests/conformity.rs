use base64::{Engine as _, engine::general_purpose};
use devolutions_crypto::{
    Argon2Parameters, KdfEncryptedData,
    ciphertext::{Ciphertext, CiphertextVersion, encrypt_asymmetric},
    key::{PrivateKey, PublicKey, SecretKey},
    key_encapsulation::{EncapsulatedKey, decapsulate},
    password_hash::PasswordHash,
    utils::{derive_key_argon2, derive_key_pbkdf2},
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
        .decode("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")
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

// Post-quantum (X-Wing) vectors. All share the same `KeyVersion::V2` keypair.
const X_WING_PRIVATE_KEY: &str = "DQwBAAEAAgA1nERi4Of6p1Sg60NSw98tDx4OuBZtVR+CpVe+n1VDLg==";
const X_WING_PUBLIC_KEY: &str = "DQwBAAIAAgBJegPKg7n38TKlpy2f+rrR0Sw7NZQlGG6SxcqX5S+TtRKMib0VA1Q7QV9I2U2L2GuJq5ZPfDRFiSd48bFSkxe6SyMioVFTE13HJ3dR9o5qmSmCzA+MJnyDsyWhRRc5l0/mFWIM7F3uABS8pAIsVBh3ghOq8ZZLSgpuyBd810yJKI8sFXZDKDnFWgpZMM9q12P29wr4p72WVsc+Mq1JUWVpCLyl5EyadXW7VUzct0GTyrZuR1BRA5q5e6HukbDnI5TKrEZkIpFkY6fu9Mk1oxK45Ai/YpL46wIN2wAtU1wWlk+zYXedcYjlMs0WYmDqjIHLusbdyQvnNDKx+09QRVLFAb2Xd8vklkd5ena1O4cSoVAo4CZfYS+7PMTO1VDYuCK3R1d4o39PqqPda5nQbCuRCYKQRIny2K0yVKQkZWaHVAN3ASeRFgvwV3Hhg1ifiqL/8p5sAb+EyRQHMWeDQFQUdJlOOkTDAqLMbK4s+3a4BbHVY1RaeEVCJ3hECYZDYFnA0WV7kWOwoQY1kXJLdU+a5sjgCUI7HMZi0UVwyh64JI+fJIJgEwLTCWW1zK8hCJ60HB0EhmkQdFW1OxdTGQ5wAqTUAsLeuzA7MD+AljEHx8pQGHNoRTWKALBkkVA+eFp/q7ra1LtqoJKlKMQWk2wpGGKS9D4YLEpDsgTQE5bWe1KuwCppswcN9bclhgHKZTQ5I3bLp2NO6icn8wHGxquK+0PXkGim2bTiSYDCGKtlGaAc+4ZBfLN6009adixR8sRQusmGeJMWomd6l8KFEpnxNG0/E1KJZwhDm8wdV7c9SggK5cH5Kqx28bBpQYn7MWKI+7ZLsrgnXGFFwEtrlFXBYLyIAMXOIwSucW42w5yWtwjsoF/RhM2/JFiYB4MvaTSoNJUTCZExyDsDbG3IF1+R0XGba2kqEhuqFbnEpoOhOnYMxQnaaZ1jkLhVSyt7Jwtfgsm++5wK+HpiJQKhhmWAJhq5V09Jgn+pSyHPQsV1R6qTC7APCRCqAo6e2RTCMWzINXopLMBUkjG1xWyYQ4mWoHZF+DmFI3U74A/wtSfnMJxW5AicGCuPKFcXGs7s+YTAko86ypHbeLpVp2PH8HH5ELEcHBi+AnWfE7P4y1XdlpXFlmeCF0c3oc2QSWg9mJ39iq2EFwqkyp23Ug6EkG3rurIv6BbEO1TOamw25Gtryz3+sxpj2ICvqzeyJZnkxFF9trlM5J0mci+ndw4A9yXN+7Oows9W90hFcCYilhaEsLjuUVCdsS7UywPrdJt5zJP73DhgLGVf/A+JOcL3iWmtclTmwgkbZn2K6U4r5ZcCinusdJms2ATXi1fkuHqZUwr0wihqwcTvy8ZVbBvFjEX5Ky9toz/X9o1Z55UHGFFp5KuZOztdWW206KnW2sob6maag0FCNg9slBCz1CO/IbOgOM75JWSdJoo8t0GaGWF8d3fW8zGOsrHTFl4dRxK/I03QUaqAJqNOdM4FRD7W6BBlwrRuEbll0nMMwowQfDDF4T4NwpXD82oIWa6CYs2tsglNJEAuMlyXXICQP2WWI4Q6lOqS6dSKk9lkl7wD2DNIvsqd4QaW4ewdDmjqFEV8m7KjJi2BStGVYaAGkpXoAj19";

fn x_wing_private_key() -> PrivateKey {
    PrivateKey::try_from(
        general_purpose::STANDARD
            .decode(X_WING_PRIVATE_KEY)
            .unwrap()
            .as_slice(),
    )
    .unwrap()
}

#[test]
fn test_x_wing_keypair_v2() {
    let private_key = x_wing_private_key();
    let public_key = PublicKey::try_from(
        general_purpose::STANDARD
            .decode(X_WING_PUBLIC_KEY)
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let ciphertext = encrypt_asymmetric(b"testdata", &public_key, CiphertextVersion::V3).unwrap();

    assert_eq!(
        ciphertext.decrypt_asymmetric(&private_key).unwrap(),
        b"testdata"
    );
}

#[test]
fn test_asymmetric_decrypt_v3() {
    let ciphertext = Ciphertext::try_from(general_purpose::STANDARD.decode("DQwCAAIAAwCm2YjCoBofihIBaK5pfKKOfY0Ijhhvv+X8fw9bOWk/6TdrsxZBU9bucUBY37Ot1IuMGwBUU+eV5MQz/rTG5NoBai2licmRGBL/EJePhCPg3rgDtOajBszyyOkVVEHt4C+uznm8pJCaiw+zcG3E2pwLBRakUuUhqzHxolzVxRdZ8BaQUhNZSExDB7us3BoEhyiGpkXqKb8JWWrexzWRU/1p/ie6oP+lPG/uHK9ifAZ7k/pOty0lnIaH7R6XQ8tffM6kvyA2Cp7QHqzmGWUct8lKxy4BI7wRzNjpmIbhyHRwgZU5svTiHcccvFIYEqcZoU9gY9zBps9bkJIVK4v9AIlPtY1Ay55kE3Ze5gtHxBEvo1UaXT1+EOmOolqCqIv9Q8sbJIgFhqfkpoX3zy395FfI3C5mgqzTtW+xBOdpzxtnE3u3+M9ModNg4j6cMu6F242TFFJABdKk1CAV+jZ4WeBqt8c3VCnJGvJWGUpM8E6x3UL/C5tsDR7Ifzf39zoYGjEuo6pL9RFfA/VV1iGDFBdRmeVmoGnX0RME5epUuSET/ooymu4Vqn5INi+RTy3nIJwcyeSHEBlMYC0xVWi/veTKkoYfI6qxSYI8oxJXM8uSuZnB7TeKLshMOmt3jFM6bSyarAPlgMkbGDH+zXWe478Po4UcveequOsNABECYNET7fq6J/3ovfZ+6lMBIi2Hl2IMA5Ii/WXAv4N9ihUppFgYdPXooAOaYFoan8ntZKT+88L+s6hzUce9AhTjl+Ts2nWmdowo3rc/sGbH7LqllvGEBVohanBT8Tjy+4Q+zeN6xVpQIW3qcbeI2EE91uRrkVJwTKarB2TEYuTyys2Q3PLUX7/WUj99XBqZfOUEB9Na1F6JgPIL1+PL4Rfe5vSZySsdQi6qk+0bpd9tcauiUQokhzKiBZeLIi9VRimFpU0Qng3NmbopOKPTIBekowLhsyZgrFCqEANdOc8Jhy/OrssharUIu0mNZXgoFfJHn6kmsXgJejQikBRwUq/eUXqoz+k/ddcidKkKlJ1Mr5i7nzMPgODX8/WK229/qsIXq/cGZM9844fgeEcSkQQN9CPwbkw2k/dgWf28xfKGzMAzWpSnUwkC7toubDtYWrMoQWkpTN/nhMbAtTDBn8xrdMu5gkpERf6EeN1QURgje6dx10KpniC6/Vy7Zgg7lmn6h9o3PVpWv4oSlr3YObnUM8UgDsiRommWcBdJ8axl4/yvfeEa882DRJUAWU6nZKyunm1TgSrtFevb/72kJidpNQwmfXmy3gDC/rSXcsmnFSMGdc7a40dNFsmDZVui5386GsQk/Uta6h1zsZmqoW7AuaSDqhNo44Gbr5b57zjSwP9okkPvUVi2avFVIZsZFBl7FlWLVwb0d6HEzWVX93ZRxFosUBo5aS+btaT4YF9z++4xjST83whVU3o4TOQTq9mgAV/91JRB5+fT6P2wkOuuUuPe6gemH50LV0cYbxAHECt4OggFaAjHodoPqW0VRkU74M3xzZbKusiQv0YHDWsvqRzUuJ46XVWl+ZW2jVulTgmaSg/s").unwrap().as_slice()).unwrap();

    let result = ciphertext
        .decrypt_asymmetric(&x_wing_private_key())
        .unwrap();

    assert_eq!(result, b"testdata");
}

#[test]
fn test_asymmetric_decrypt_aad_v3() {
    let ciphertext = Ciphertext::try_from(general_purpose::STANDARD.decode("DQwCAAIAAwCY+aboyvWcG4QDu2lQfA8io0hemIghqdHjzt2b/nUpa3p9hMmnquY2zaMaugi3Lq1DyQuiau7BgDbv2Ew0fvumqvNi6EtmOOTgTp4cyCFQxBxq1dw4k1o1kdGm4I7W1h+NMnJfQ5tPjE2xRDKgDlkoOqdWv9AJmY2jFBQ65x4tVOl+a2VyicbFUNz6wpjN1vytLaWe3KZhckYt/yx6bZOJ13U7weaGezcGJwbcPTKUALSGqe6apJbOzVYxByq33j5652Cc8uL8USEJJ0pgvAYsukvgAtqycnz9wOi7dtmmmBa/2Ubzyo5U/5O6LBqHjv1irvQ3YIqn4XRXaXJ4Odik70xlG0LsiTBymr0SgGMQq0yIzoxfDOCyM6O5rBDpqlFKs+KdyN/luU+FzvJuSfR+WechpzJKW7pT5iKB/UQefXb5Dr8IMmRH7ca90Miq30yk+2lYnhI7i/K9kDoh/rM6j1xfk/j4UMWWVLnbAK3ZRbioCYF4H47ya1yQqYdrj3ZpiNLcLy2Oj8suAeVDyJFqIwDHFlsCfrgSnr1OJ5kWRkb5y/BW0S/33MTJpewAc7RztE/Dv5UfpY15GjVlY5LRj8L3oXmfF8qOvKAnzoo4pxqZMnKXCZkbyAf8FRYEF2e/J29KrzWBBVTAQMhMNqaHMw55Q2U8Cv5/eioPw1YmHYDU9E7+xmTM0KLK1/fcRQCnmFY8nVs3FRL1DdkIowjSWV5OwiWrHKYcMth5Kc556XI6VN46zOKYCEdjRwNuz9o3bCTCTeHmVFYspcwey3dRkzlKKJpmg69kQlM+5V/Ts+PY4yQ0eY0yx/vcZAmdp3H3t6LddHiOSd811z9SlsGK0YvbDgx8iRjEPFnwRlm6aly1fBYXWlk3JxvzOJCYwTqo2Q3xi4wMRA6FVwDRmDlazMSZ/qu+l5QbkXqfXAK4dCZbxksr9IXUINDcakLK3laD+iTBw+PSRfb0nyKkOoq+KbBZHRI94cGEm1Pn0Q88gPME2X02lfiMNe3fPwGPMlf6D0Ovykl0DI+IvahRqBE5h4LhneHD9j6PKuJzSy83EKsS+uLQ7nuYGoNpZFu/8wNEdkylVpCvY4SRVmAcmzBcbvv8V1NZek6sYY8BtKY7cCeyIr9wq9MMw3ZypMufpE1n5wIaQ+Y9Smgc9Vb8eV5Gsjsaam6mhzwJ38HqKmFBWVf886MhE4OuuBUEI76EeSXf3TAG+MIFqoKwfqJsLmtznDNBGDbmqC9g1J6jTplMH0zPl95LNL0SMS6+ObnVPHxJ/QBExSMbIvW7yTQ03dX2WawBbdNTee41Ev6cGQsXWnMjnOfAlIfwj1z6ZB2umYeAsRtju+0idLmqARnLnVDp2oIn4nAckkT8qoOMOVw81xvL5UYoepJREOr/k3X3tfLtFeaY4VtBrpGvUIo37hWYiDHP/vqdR7yzrkx3O3b/UVsV3JLGTIjf/brGErTsNmly+IAkR4MzwbQfezCxgCcpalHS/3GWUTWf3ureWok3q7aVj8slI7zmfFMpgdLFvVekdKUCVsF/1BMhB6gwfWuV").unwrap().as_slice()).unwrap();
    let aad = b"this is some public data";

    let result = ciphertext
        .decrypt_asymmetric_with_aad(&x_wing_private_key(), aad)
        .unwrap();

    assert_eq!(result, b"testdata");
}

#[test]
fn test_key_decapsulation_v1() {
    let encapsulated_key = EncapsulatedKey::try_from(general_purpose::STANDARD.decode("DQwKAAAAAQAdAidiTcgaZ0lFtIEr7TWNrzDq7XkFBWLSDqU+tWi68zmUXyMMxwXPSwYuX0QLAhArzNyMJXqo88zrYR+AfAeeeBVpRLq4naSDQ12j0d3gsNFbhBRzCbaa/WL92DwNQSZoA3Z1bSToRkxepJW7kcqTHs6DfFn9WAWBpU8Qul3iHWfiFqY0/xNdzMfb0H61qaLlB9C762rXwqKw5jGF1XOih6q2jwZjKOp7bZK+JNXMTb9X5BqJl/spn3FKLIhOLp85M26hDdJM1THqNCkm8/xYWVA6alkdfL9ZGE1IxJv9i8B5rW0qK7sG54a+ZuGnSaf3TZiSSR1D519WHttp+rlI/yNNWXxsOcmZmOEKw4DX2XQS5IQ9S1wflnaBwRVyBIfMUILnKSWZ0EwlgCs6XKnFy/5NqRNyZbDSAcJ+ROA/8H7yMrYQV0ilwl9mXAx9Ip9AHYsrrjC2IM3iWUBR6gqM7bwmBVb/eN51WwSXK8Vcy4FPeeii6VvFND/rEiiERhmRBRFhDNYmf5tARfBgccPw62GO56IjkBuyZhoUZ6DB8Uy8nVxcoe0hpN6fiCW10S8cBWdKtyJObkl9oqRbxmB21bKSJS/yz3owxqivTSaaLAT5HQy6FnPFYoOoG57Vp/WEIU00C5GwuAs6MUbuBBiZtjeJMRkV/HJidgH1WPIx0Xs7EKf/N4kkVok2D9ZdL9jSbLV69QR5SeW8M2U9B+1oqZghXpI4en20WEvGxEJ1ALCd2VlQqK76vLZpXX0DSlhMv14VzR7fUiZiurpH8S/tbieCMijdeWt9a5lnWTzWE0IVgALHLH2T82R6RJSIbBE7EwWziYO3Vm0Tus3iY+GxzSRqaBHc0oCsbFDFG3BkWF7gWOeTElnz7taRRqKnolN4VWfPRQ6Glmq8ml/83HTQFJfW7yI5jKp+I9vSCZ/tAcOTaneUDZ6cveDfPIWnLsSld2t/1MtXlzbRHGqGfe3nyU94TU7WDeFGcgL+EykMu58RVxVT5yefqy6kTlnkUWqr7j2EwrayzT0D5d4dvzJp38SXDsHL2/W2bsmv7WipnjFAp8xh0gNd5AGysTf+xJ8+Qv6D/aQF8JgEvVn+E7i5JcAWFIHelVupk6JJPX7KNalqN3LqBwuFm2gb7rTkdGWGoFw23+1NeyfuLPWSPq79NuzKw/5PqhQWlwDxOC88aF8lYLB3QrT8AcF/2ciwaT2j33YpRdhkFVbPrwNUPFsVV+LA4NplDywB81mABsfS3JSHhiXPLAKZhHV56qmM2gFG5dicrHOm6k7s3mDAfH/LUNrHgUs7ihYr3BzCocIfq//1RDf9NmJWj9rKbj3NpeAGnkMD68W82xv5SAYpkC6E5mZMJD1O6CBmgnPkLc6/YNxWfE/O37o18gTvjpYZourUxsX1BwAnoLjz+nptQJqJHzJeeA/GqaaoP+8F+LyEAxKFBIFD/XYK4xJ6N3v4OtforFb9QtvwCoMKnZvbeMEd").unwrap().as_slice()).unwrap();

    let secret_key = decapsulate(&x_wing_private_key(), &encapsulated_key).unwrap();

    assert_eq!(
        secret_key.as_bytes(),
        general_purpose::STANDARD
            .decode("hqnsrwF5qEgJsI0G4aURCcbbsshKl7Z590eicp0ArtA=")
            .unwrap()
            .as_slice()
    );
}
