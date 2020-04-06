#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use devolutions_crypto::secret_sharing::{ Share, join_shares};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    shares: Vec<Share>,
}

fuzz_target!(|data: Input| {
    let _ = join_shares(&data.shares);
});
