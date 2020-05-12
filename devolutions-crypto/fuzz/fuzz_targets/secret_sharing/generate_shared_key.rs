#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use devolutions_crypto::secret_sharing::{ generate_shared_key, SecretSharingVersion };

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    n_shares: u8,
    threshold: u8,
    length: u8, // using a u8 will prevent absurdly long numbers
    version: SecretSharingVersion,
}

fuzz_target!(|data: Input| {
    let _ = generate_shared_key(data.n_shares, data.threshold, data.length as usize, data.version);
});
