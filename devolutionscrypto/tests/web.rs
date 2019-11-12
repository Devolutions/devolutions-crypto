extern crate base64;
extern crate wasm_bindgen_test;

use std::convert::TryFrom as _;
use wasm_bindgen_test::*;

use devolutionscrypto::DcDataBlob;

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    let data = "test".as_bytes();
    let key = base64::decode("dpxbute8LZ4tqpw1pVWyBvMzOtm+OJQPcIsU52+FFZU=").unwrap();

    let ciphertext = DcDataBlob::encrypt(data, &key, 0).unwrap();
    let ciphertext_vec: Vec<u8> = ciphertext.into();

    let ciphertext = DcDataBlob::try_from(ciphertext_vec.as_slice()).unwrap();
    let plaintext = ciphertext.decrypt(&key).unwrap();

    assert_eq!(plaintext, data);
}
