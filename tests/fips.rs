// Tests for the version 3 (FIPS) primitives and for the restrictions of the `fips` feature.
// The decryption of the older versions (migration) is also covered by tests/conformity.rs.
#![cfg(feature = "fips")]

use base64::{Engine as _, engine::general_purpose};
use devolutions_crypto::ciphertext::{
    Ciphertext, CiphertextVersion, encrypt, encrypt_asymmetric, encrypt_asymmetric_with_aad,
    encrypt_with_aad, encrypt_with_secret_key,
};
use devolutions_crypto::derive_encrypt::{KdfEncryptedData, encrypt_with_password};
use devolutions_crypto::key::{
    KeyVersion, PrivateKey, PublicKey, SecretKey, generate_keypair, generate_secret_key,
    mix_key_exchange,
};
use devolutions_crypto::key_derivation::{Argon2, DerivationParameters, Pbkdf2, derive_key};
use devolutions_crypto::password_hash::{
    PasswordHash, PasswordHashVersion, hash_password, hash_password_with_parameters,
};
use devolutions_crypto::signature::{Signature, SignatureVersion, sign, try_sign};
use devolutions_crypto::signing_key::{
    SigningKeyPair, SigningKeyVersion, SigningPublicKey, generate_signing_keypair,
};
use devolutions_crypto::utils::derive_key_pbkdf2;
use devolutions_crypto::{Error, KeyDerivationVersion};

use std::convert::TryFrom;

const HEADER_LEN: usize = 8;

fn version_of(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[6], data[7]])
}

// ── Module ──────────────────────────────────────────────────────────────────

#[test]
fn module_runs_in_fips_mode() {
    devolutions_crypto::fips::ensure_fips_mode().unwrap();
}

// ── Ciphertext ──────────────────────────────────────────────────────────────

#[test]
fn symmetric_latest_is_v3() {
    let key = devolutions_crypto::utils::generate_key(32).unwrap();
    let data = b"This is a very complex string of character that we need to encrypt";

    let encrypted: Vec<u8> = encrypt(data, &key, CiphertextVersion::Latest)
        .unwrap()
        .into();
    assert_eq!(version_of(&encrypted), 3);

    let explicit: Vec<u8> = encrypt(data, &key, CiphertextVersion::V3).unwrap().into();
    assert_eq!(version_of(&explicit), 3);

    let encrypted = Ciphertext::try_from(encrypted.as_slice()).unwrap();
    assert_eq!(encrypted.decrypt(&key).unwrap(), data);
}

#[test]
fn symmetric_v3_is_randomized() {
    let key = b"0123456789abcdefghijkl";

    let a: Vec<u8> = encrypt(b"data", key, CiphertextVersion::V3).unwrap().into();
    let b: Vec<u8> = encrypt(b"data", key, CiphertextVersion::V3).unwrap().into();
    assert_ne!(a, b);
}

#[test]
fn symmetric_v3_empty_plaintext() {
    let key = b"0123456789abcdefghijkl";

    let encrypted: Vec<u8> = encrypt(b"", key, CiphertextVersion::V3).unwrap().into();
    let encrypted = Ciphertext::try_from(encrypted.as_slice()).unwrap();
    assert_eq!(encrypted.decrypt(key).unwrap(), b"");
}

#[test]
fn symmetric_v3_aad() {
    let key = b"0123456789abcdefghijkl";
    let data = b"secret";
    let aad = b"This is some public data that we want to authenticate";
    let wrong_aad = b"this is some public data that we want to authenticate";

    let encrypted: Vec<u8> = encrypt_with_aad(data, key, aad, CiphertextVersion::V3)
        .unwrap()
        .into();
    let encrypted = Ciphertext::try_from(encrypted.as_slice()).unwrap();

    assert_eq!(encrypted.decrypt_with_aad(key, aad).unwrap(), data);
    assert!(encrypted.decrypt_with_aad(key, wrong_aad).is_err());
    assert!(encrypted.decrypt(key).is_err());
}

#[test]
fn symmetric_v3_wrong_key() {
    let encrypted = encrypt(b"secret", b"right key", CiphertextVersion::V3).unwrap();
    assert!(matches!(
        encrypted.decrypt(b"wrong key"),
        Err(Error::InvalidMac)
    ));
}

#[test]
fn symmetric_v3_tampering_is_detected() {
    let key = b"0123456789abcdefghijkl";
    let encrypted: Vec<u8> = encrypt(b"some secret data", key, CiphertextVersion::V3)
        .unwrap()
        .into();

    // Every byte of the payload (salt, nonce, ciphertext and tag) is authenticated
    for i in HEADER_LEN..encrypted.len() {
        let mut tampered = encrypted.clone();
        tampered[i] ^= 0x01;

        let tampered = Ciphertext::try_from(tampered.as_slice()).unwrap();
        assert!(
            tampered.decrypt(key).is_err(),
            "byte {i} is not authenticated"
        );
    }
}

#[test]
fn symmetric_v3_header_is_authenticated() {
    let key = b"0123456789abcdefghijkl";
    let mut encrypted: Vec<u8> = encrypt(b"some secret data", key, CiphertextVersion::V3)
        .unwrap()
        .into();

    // Flip the subtype to asymmetric: either parsing or decryption must fail
    encrypted[4] = 2;
    if let Ok(tampered) = Ciphertext::try_from(encrypted.as_slice()) {
        assert!(tampered.decrypt(key).is_err());
    }
}

#[test]
fn symmetric_v3_truncated() {
    let key = b"0123456789abcdefghijkl";
    let encrypted: Vec<u8> = encrypt(b"", key, CiphertextVersion::V3).unwrap().into();

    // salt (32) + nonce (12) + tag (16)
    assert_eq!(encrypted.len(), HEADER_LEN + 32 + 12 + 16);

    for len in HEADER_LEN..encrypted.len() {
        assert!(matches!(
            Ciphertext::try_from(&encrypted[..len]),
            Err(Error::InvalidLength)
        ));
    }
}

#[test]
fn secret_key_v3() {
    let key = generate_secret_key(KeyVersion::Latest);
    let key_bytes: Vec<u8> = key.clone().into();
    assert_eq!(version_of(&key_bytes), 3);

    let parsed = SecretKey::try_from(key_bytes.as_slice()).unwrap();
    assert_eq!(parsed.as_bytes(), key.as_bytes());

    let encrypted: Vec<u8> = encrypt_with_secret_key(b"data", &key, CiphertextVersion::Latest)
        .unwrap()
        .into();
    assert_eq!(version_of(&encrypted), 3);

    let encrypted = Ciphertext::try_from(encrypted.as_slice()).unwrap();
    assert_eq!(encrypted.decrypt_with_secret_key(&parsed).unwrap(), b"data");
}

#[test]
fn asymmetric_v3() {
    let keypair = generate_keypair(KeyVersion::Latest);

    let public_bytes: Vec<u8> = keypair.public_key.clone().into();
    let private_bytes: Vec<u8> = keypair.private_key.clone().into();
    assert_eq!(version_of(&public_bytes), 3);
    assert_eq!(version_of(&private_bytes), 3);

    let public_key = PublicKey::try_from(public_bytes.as_slice()).unwrap();
    let private_key = PrivateKey::try_from(private_bytes.as_slice()).unwrap();

    let encrypted: Vec<u8> =
        encrypt_asymmetric(b"testdata", &public_key, CiphertextVersion::Latest)
            .unwrap()
            .into();
    assert_eq!(version_of(&encrypted), 3);

    let encrypted = Ciphertext::try_from(encrypted.as_slice()).unwrap();
    assert_eq!(
        encrypted.decrypt_asymmetric(&private_key).unwrap(),
        b"testdata"
    );

    // Symmetric decryption of an asymmetric ciphertext is a type error
    assert!(matches!(
        encrypted.decrypt(b"key"),
        Err(Error::InvalidDataType)
    ));
}

#[test]
fn asymmetric_v3_aad() {
    let keypair = generate_keypair(KeyVersion::V3);
    let aad = b"public data";

    let encrypted =
        encrypt_asymmetric_with_aad(b"testdata", &keypair.public_key, aad, CiphertextVersion::V3)
            .unwrap();

    assert_eq!(
        encrypted
            .decrypt_asymmetric_with_aad(&keypair.private_key, aad)
            .unwrap(),
        b"testdata"
    );
    assert!(
        encrypted
            .decrypt_asymmetric_with_aad(&keypair.private_key, b"other")
            .is_err()
    );
    assert!(encrypted.decrypt_asymmetric(&keypair.private_key).is_err());
}

#[test]
fn asymmetric_v3_wrong_private_key() {
    let keypair = generate_keypair(KeyVersion::V3);
    let other = generate_keypair(KeyVersion::V3);

    let encrypted =
        encrypt_asymmetric(b"testdata", &keypair.public_key, CiphertextVersion::V3).unwrap();
    assert!(encrypted.decrypt_asymmetric(&other.private_key).is_err());
}

#[test]
fn asymmetric_v3_tampering_is_detected() {
    let keypair = generate_keypair(KeyVersion::V3);
    let encrypted: Vec<u8> =
        encrypt_asymmetric(b"testdata", &keypair.public_key, CiphertextVersion::V3)
            .unwrap()
            .into();

    for i in HEADER_LEN..encrypted.len() {
        let mut tampered = encrypted.clone();
        tampered[i] ^= 0x01;

        // A tampered ephemeral public key is usually rejected while parsing
        if let Ok(tampered) = Ciphertext::try_from(tampered.as_slice()) {
            assert!(
                tampered.decrypt_asymmetric(&keypair.private_key).is_err(),
                "byte {i} is not authenticated"
            );
        }
    }
}

#[test]
fn asymmetric_v3_rejects_invalid_ephemeral_key() {
    let keypair = generate_keypair(KeyVersion::V3);
    let mut encrypted: Vec<u8> =
        encrypt_asymmetric(b"testdata", &keypair.public_key, CiphertextVersion::V3)
            .unwrap()
            .into();

    // Replace the ephemeral public key with a point that is not on the curve
    encrypted[HEADER_LEN + 1..HEADER_LEN + 65].fill(0xFF);
    assert!(Ciphertext::try_from(encrypted.as_slice()).is_err());
}

#[test]
fn asymmetric_rejects_mismatched_key_versions() {
    let legacy = generate_keypair(KeyVersion::V1);
    let fips = generate_keypair(KeyVersion::V3);

    // A V3 ciphertext cannot be produced for an X25519 key
    assert!(matches!(
        encrypt_asymmetric(b"data", &legacy.public_key, CiphertextVersion::Latest),
        Err(Error::InvalidDataType)
    ));

    // A V3 ciphertext cannot be decrypted with an X25519 key
    let encrypted = encrypt_asymmetric(b"data", &fips.public_key, CiphertextVersion::V3).unwrap();
    assert!(matches!(
        encrypted.decrypt_asymmetric(&legacy.private_key),
        Err(Error::InvalidDataType)
    ));
}

// ── Key ─────────────────────────────────────────────────────────────────────

#[test]
fn key_exchange_v3() {
    let bob = generate_keypair(KeyVersion::Latest);
    let alice = generate_keypair(KeyVersion::Latest);

    let bob_shared = mix_key_exchange(&bob.private_key, &alice.public_key).unwrap();
    let alice_shared = mix_key_exchange(&alice.private_key, &bob.public_key).unwrap();

    assert_eq!(bob_shared.len(), 32);
    assert_eq!(bob_shared, alice_shared);
}

#[test]
fn key_exchange_rejects_mismatched_versions() {
    let legacy = generate_keypair(KeyVersion::V1);
    let fips = generate_keypair(KeyVersion::V3);

    assert!(matches!(
        mix_key_exchange(&legacy.private_key, &fips.public_key),
        Err(Error::InconsistentVersion)
    ));
    assert!(matches!(
        mix_key_exchange(&fips.private_key, &legacy.public_key),
        Err(Error::InconsistentVersion)
    ));
}

#[test]
fn key_v3_rejects_invalid_encodings() {
    let keypair = generate_keypair(KeyVersion::V3);
    let public_bytes: Vec<u8> = keypair.public_key.into();
    let private_bytes: Vec<u8> = keypair.private_key.into();

    // Compressed point marker
    let mut compressed = public_bytes.clone();
    compressed[HEADER_LEN] = 0x02;
    assert!(PublicKey::try_from(compressed.as_slice()).is_err());

    // Not on the curve
    let mut off_curve = public_bytes.clone();
    off_curve[HEADER_LEN + 1..].fill(0xFF);
    assert!(PublicKey::try_from(off_curve.as_slice()).is_err());

    // Wrong length
    assert!(matches!(
        PublicKey::try_from(&public_bytes[..public_bytes.len() - 1]),
        Err(Error::InvalidLength)
    ));

    // Zero and out-of-range scalars
    let mut zero = private_bytes.clone();
    zero[HEADER_LEN..].fill(0);
    assert!(PrivateKey::try_from(zero.as_slice()).is_err());

    let mut too_big = private_bytes.clone();
    too_big[HEADER_LEN..].fill(0xFF);
    assert!(PrivateKey::try_from(too_big.as_slice()).is_err());
}

// ── Signature ───────────────────────────────────────────────────────────────

#[test]
fn signature_v3() {
    let data = b"this is a test";

    let keypair = generate_signing_keypair(SigningKeyVersion::Latest);
    let public = keypair.get_public_key();
    let other_public = generate_signing_keypair(SigningKeyVersion::V3).get_public_key();

    let keypair_bytes: Vec<u8> = keypair.clone().into();
    let public_bytes: Vec<u8> = public.clone().into();
    assert_eq!(version_of(&keypair_bytes), 3);
    assert_eq!(version_of(&public_bytes), 3);

    let signature = sign(data, &keypair, SignatureVersion::Latest);
    let signature_bytes: Vec<u8> = signature.clone().into();
    assert_eq!(version_of(&signature_bytes), 3);

    assert!(signature.verify(data, &public));
    assert!(!signature.verify(b"this is wrong", &public));
    assert!(!signature.verify(data, &other_public));

    // Serialization roundtrip
    let keypair = SigningKeyPair::try_from(keypair_bytes.as_slice()).unwrap();
    let public = SigningPublicKey::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();

    assert!(signature.verify(data, &public));
    assert!(sign(data, &keypair, SignatureVersion::V3).verify(data, &public));
}

#[test]
fn signature_v3_tampering_is_detected() {
    let keypair = generate_signing_keypair(SigningKeyVersion::V3);
    let public = keypair.get_public_key();
    let signature: Vec<u8> = sign(b"data", &keypair, SignatureVersion::V3).into();

    for i in HEADER_LEN..signature.len() {
        let mut tampered = signature.clone();
        tampered[i] ^= 0x01;

        let tampered = Signature::try_from(tampered.as_slice()).unwrap();
        assert!(!tampered.verify(b"data", &public));
    }
}

#[test]
fn signature_rejects_mismatched_versions() {
    let legacy = generate_signing_keypair(SigningKeyVersion::V1);
    let fips = generate_signing_keypair(SigningKeyVersion::V3);

    assert!(matches!(
        try_sign(b"data", &legacy, SignatureVersion::V3),
        Err(Error::InvalidDataType)
    ));
    assert!(matches!(
        try_sign(b"data", &fips, SignatureVersion::V1),
        Err(Error::InvalidDataType)
    ));

    // `Latest` follows the keypair, so legacy keys can still sign until they are rotated
    let legacy_signature = sign(b"data", &legacy, SignatureVersion::Latest);
    let legacy_bytes: Vec<u8> = legacy_signature.clone().into();
    assert_eq!(version_of(&legacy_bytes), 1);
    assert!(legacy_signature.verify(b"data", &legacy.get_public_key()));

    // A signature never verifies with a key of another version
    let fips_signature = sign(b"data", &fips, SignatureVersion::Latest);
    assert!(!fips_signature.verify(b"data", &legacy.get_public_key()));
    assert!(!legacy_signature.verify(b"data", &fips.get_public_key()));
}

#[test]
fn signing_key_v3_rejects_mismatched_pair() {
    let a: Vec<u8> = generate_signing_keypair(SigningKeyVersion::V3).into();
    let b: Vec<u8> = generate_signing_keypair(SigningKeyVersion::V3).into();

    // Private key of `a` with the public key of `b`
    let mut mixed = a[..HEADER_LEN + 32].to_vec();
    mixed.extend_from_slice(&b[HEADER_LEN + 32..]);

    assert!(SigningKeyPair::try_from(mixed.as_slice()).is_err());
}

// ── Password hash and key derivation ────────────────────────────────────────

#[test]
fn password_hash_v3() {
    let password = b"thisisaveryveryverystrongPa$$w0rd";

    let hash = hash_password(password, PasswordHashVersion::Latest).unwrap();
    let hash_bytes: Vec<u8> = hash.into();
    assert_eq!(version_of(&hash_bytes), 3);

    let hash = PasswordHash::try_from(hash_bytes.as_slice()).unwrap();
    assert!(hash.verify_password(password));
    assert!(!hash.verify_password(b"averybadpassword"));
}

#[test]
fn password_hash_v3_custom_parameters() {
    let password = b"thisisaveryveryverystrongPa$$w0rd";
    let params = Pbkdf2::with_params(1000).parameters().unwrap();

    let hash = hash_password_with_parameters(password, params).unwrap();
    let hash_bytes: Vec<u8> = hash.into();
    assert_eq!(version_of(&hash_bytes), 3);

    let hash = PasswordHash::try_from(hash_bytes.as_slice()).unwrap();
    assert!(hash.verify_password(password));
}

#[test]
fn key_derivation_v3() {
    let password = b"a very strong password";

    let (key, params) = derive_key(password, KeyDerivationVersion::Latest).unwrap();
    let key_bytes: Vec<u8> = key.clone().into();
    let params_bytes: Vec<u8> = params.into();
    assert_eq!(version_of(&key_bytes), 3);
    assert_eq!(version_of(&params_bytes), 3);

    let params = DerivationParameters::try_from(params_bytes.as_slice()).unwrap();
    assert_eq!(params.derive(password).unwrap().as_bytes(), key.as_bytes());
    assert_ne!(
        params.derive(b"another password").unwrap().as_bytes(),
        key.as_bytes()
    );
}

#[test]
fn key_derivation_v3_matches_pbkdf2_reference() {
    // The FIPS module output must match the RustCrypto PBKDF2-HMAC-SHA256 implementation
    let password = b"testPa$$word1234";
    let salt = general_purpose::STANDARD
        .decode("tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA=")
        .unwrap();

    let (key, _) = Pbkdf2::with_params(1000)
        .derive_with_salt(password, &salt)
        .unwrap();

    assert_eq!(
        key.as_bytes(),
        derive_key_pbkdf2(password, &salt, 1000, 32).as_slice()
    );
}

#[test]
fn key_derivation_v3_enforces_fips_ranges() {
    let salt = [0u8; 16];

    // Too few iterations
    assert!(matches!(
        Pbkdf2::with_params(999).derive_with_salt(b"password", &salt),
        Err(Error::NotFipsApproved)
    ));
    assert!(matches!(
        Pbkdf2::with_params(0).parameters(),
        Err(Error::NotFipsApproved)
    ));

    // Salt too short
    assert!(matches!(
        Pbkdf2::new().derive_with_salt(b"password", &salt[..15]),
        Err(Error::NotFipsApproved)
    ));

    // Parameters below the minimums are rejected while parsing
    let params: Vec<u8> = Pbkdf2::with_params(1000).parameters().unwrap().into();
    let mut weak = params.clone();
    weak[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&999u32.to_le_bytes());
    assert!(DerivationParameters::try_from(weak.as_slice()).is_err());

    let mut zero = params;
    zero[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&0u32.to_le_bytes());
    assert!(DerivationParameters::try_from(zero.as_slice()).is_err());
}

#[test]
fn derive_encrypt_v3() {
    let password = b"a very strong password";
    let params = Pbkdf2::new().parameters().unwrap();

    let blob: Vec<u8> =
        encrypt_with_password(b"secret", password, params, CiphertextVersion::Latest)
            .unwrap()
            .into();

    let blob = KdfEncryptedData::try_from(blob.as_slice()).unwrap();
    assert_eq!(blob.decrypt_with_password(password).unwrap(), b"secret");
    assert!(blob.decrypt_with_password(b"wrong password").is_err());
}

// ── Legacy versions cannot be produced ──────────────────────────────────────

#[test]
fn legacy_encryption_is_rejected() {
    let key = b"0123456789abcdefghijkl";
    let legacy_keypair = generate_keypair(KeyVersion::V1);

    for version in [CiphertextVersion::V1, CiphertextVersion::V2] {
        assert!(matches!(
            encrypt(b"data", key, version),
            Err(Error::NotFipsApproved)
        ));
    }

    assert!(matches!(
        encrypt_asymmetric(b"data", &legacy_keypair.public_key, CiphertextVersion::V2),
        Err(Error::NotFipsApproved)
    ));
}

#[test]
fn legacy_password_hash_is_rejected() {
    for version in [PasswordHashVersion::V1, PasswordHashVersion::V2] {
        assert!(matches!(
            hash_password(b"password", version),
            Err(Error::NotFipsApproved)
        ));
    }

    assert!(matches!(
        hash_password_with_parameters(b"password", Argon2::new().parameters()),
        Err(Error::NotFipsApproved)
    ));
}

#[test]
fn legacy_key_derivation_is_rejected() {
    for version in [KeyDerivationVersion::V1, KeyDerivationVersion::V2] {
        assert!(matches!(
            derive_key(b"password", version),
            Err(Error::NotFipsApproved)
        ));
    }

    assert!(matches!(
        Argon2::new().derive(b"password"),
        Err(Error::NotFipsApproved)
    ));
}

#[test]
fn legacy_derive_encrypt_is_rejected() {
    assert!(matches!(
        encrypt_with_password(
            b"data",
            b"password",
            Argon2::new().parameters(),
            CiphertextVersion::Latest
        ),
        Err(Error::NotFipsApproved)
    ));

    assert!(matches!(
        encrypt_with_password(
            b"data",
            b"password",
            Pbkdf2::new().parameters().unwrap(),
            CiphertextVersion::V2
        ),
        Err(Error::NotFipsApproved)
    ));
}

// ── Legacy versions can still be decrypted (migration) ──────────────────────

#[test]
fn migrate_v2_ciphertext_to_v3() {
    // Same vector as tests/conformity.rs
    let key = general_purpose::STANDARD
        .decode("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
        .unwrap();
    let legacy = general_purpose::STANDARD
        .decode(
            "DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=",
        )
        .unwrap();
    assert_eq!(version_of(&legacy), 2);

    let plaintext = Ciphertext::try_from(legacy.as_slice())
        .unwrap()
        .decrypt(&key)
        .unwrap();
    assert_eq!(plaintext, b"test Ciph3rtext~2");

    let migrated: Vec<u8> = encrypt(&plaintext, &key, CiphertextVersion::Latest)
        .unwrap()
        .into();
    assert_eq!(version_of(&migrated), 3);
    assert_eq!(
        Ciphertext::try_from(migrated.as_slice())
            .unwrap()
            .decrypt(&key)
            .unwrap(),
        plaintext
    );
}

#[test]
fn legacy_asymmetric_and_password_hash_still_verify() {
    // Same vectors as tests/conformity.rs
    let private_key = PrivateKey::try_from(
        general_purpose::STANDARD
            .decode("DQwBAAEAAQAAwQ3oJvU6bq2iZlJwAzvbmqJczNrFoeWPeIyJP9SSbQ==")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let ciphertext = Ciphertext::try_from(general_purpose::STANDARD.decode("DQwCAAIAAgCIG9L2MTiumytn7H/p5I3aGVdhV3WUL4i8nIeMWIJ1YRbNQ6lEiQDAyfYhbs6gg1cD7+5Ft2Q5cm7ArsGfiFYWnscm1y7a8tAGfjFFTonzrg==").unwrap().as_slice()).unwrap();
    assert_eq!(
        ciphertext.decrypt_asymmetric(&private_key).unwrap(),
        b"testdata"
    );

    let hash = PasswordHash::try_from(general_purpose::STANDARD.decode("DQwDAAAAAQAQJwAAXCzLFoyeZhFSDYBAPiIWhCk04aoP/lalOoCl7D+skIY/i+3WT7dn6L8WvnfEq6flCd7i+IcKb3GEK4rCpzhDlw==").unwrap().as_slice()).unwrap();
    assert!(hash.verify_password(b"password1"));
}
