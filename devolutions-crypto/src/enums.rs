use num_enum::{IntoPrimitive, TryFromPrimitive};
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive)]
#[zeroize(drop)]
#[repr(u16)]
pub enum DataType {
    None = 0,
    Key = 1,
    Ciphertext = 2,
    Hash = 3,
    Share = 4,
}
