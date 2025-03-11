use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "wasm32", feature = "wbindgen"))] {
        wasm_bindgen_test_configure!(run_in_browser);
        use wasm_bindgen_test::*;
        use base64::{engine::general_purpose, Engine as _};

        use devolutions_crypto::wasm;

        #[wasm_bindgen_test]
        fn test_encrypt_decrypt() {
            let data = "test".as_bytes();
            let key = general_purpose::STANDARD.decode("dpxbute8LZ4tqpw1pVWyBvMzOtm+OJQPcIsU52+FFZU=").unwrap();

            let ciphertext = wasm::encrypt(data, &key, None, None).unwrap();
            let plaintext = wasm::decrypt(&ciphertext, &key, None).unwrap();

            assert_eq!(plaintext, data);
        }

        #[wasm_bindgen_test]
        fn test_hash_password() {
            let password = "ThisIsAGoodPassword123".as_bytes();

            let hash = wasm::hash_password(password, Some(123), None).unwrap();
            assert!(wasm::verify_password(password, &hash).unwrap());

            let bad_password = "thisisabadpassword1234".as_bytes();
            assert!(!wasm::verify_password(bad_password, &hash).unwrap());
        }

        #[wasm_bindgen_test]
        fn test_key_exchange() {
            let bob_keypair = wasm::generate_keypair(None);
            let alice_keypair = wasm::generate_keypair(None);

            let bob_key = wasm::mix_key_exchange(&bob_keypair.private(), &alice_keypair.public()).unwrap();
            let alice_key = wasm::mix_key_exchange(&alice_keypair.private(), &bob_keypair.public()).unwrap();

            assert_ne!(bob_key.len(), 0);
            assert_eq!(bob_key, alice_key);
        }

        #[wasm_bindgen_test]
        fn test_generate_key() {
            let key = wasm::generate_key(Some(10)).unwrap();

            assert_eq!(key.len(), 10);
            assert_ne!(&key, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }

        #[wasm_bindgen_test]
        fn test_base64() {
            let plain = "ThIs1saTesT";
            let encoded = wasm::base64encode(plain.as_bytes());
            assert_eq!(&encoded, "VGhJczFzYVRlc1Q=");

            let decoded = wasm::base64decode(&encoded).unwrap();
            assert_eq!(decoded.as_slice(), plain.as_bytes());

            let encoded_no_pad = "VGhJczFzYVRlc1Q";
            let decoded_no_pad = wasm::base64decode(&encoded_no_pad).unwrap();
            assert_eq!(decoded_no_pad.as_slice(), plain.as_bytes());
        }

        #[wasm_bindgen_test]
        fn test_derive_key_pbkdf2() {
            let password = "ThisIsAGoodPassword123".as_bytes();
            let salt = general_purpose::STANDARD.decode("u4tv/i1228VOqoZWITseoQ==").unwrap();
            let key = wasm::derive_key_pbkdf2(password, Some(salt), Some(123), Some(32));

            assert_eq!(key, general_purpose::STANDARD.decode("RfIYPWWXRSm/SWjVXvQq1Z3n/mzxGeu/y396bAuYWTI=").unwrap());
        }
    }
}
