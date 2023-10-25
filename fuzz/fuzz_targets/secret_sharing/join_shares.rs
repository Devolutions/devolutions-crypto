#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::secret_sharing::{join_shares, Share};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    shares: Vec<Share>,
}

fuzz_target!(|data: Input| {
    let _ = join_shares(&data.shares);
});
