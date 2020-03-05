namespace Devolutions.Cryptography
{
    public enum NativeError
    {
        /// The provided data has an invalid length. Error code: -1
        InvalidLength = -1,
        /// The key length is invalid. Error code: -2
        InvalidKeyLength = -2,
        /// The length of the FFI output buffer is invalid. Error code: -3
        InvalidOutputLength = -3,
        /// The signature of the data blob does not match 0x0d0c. Error code: -11
        InvalidSignature = -11,
        /// The MAC is invalid. Error code: -12
        InvalidMac = -12,
        /// The operation cannot be done with this type. Error code: -13
        InvalidDataType = -13,
        /// The data type is unknown. Error code: -21
        UnknownType = -21,
        /// The data subtype is unknown. Error code: -22
        UnknownSubtype = -22,
        /// The data type version is unknown. Error code: -23
        UnknownVersion = -23,
        /// The data is invalid. Error code: -24
        InvalidData = -24,
        /// A null pointer has been passed to the FFI interface. Error code: -31
        NullPointer = -31,
        /// A cryptographic error occurred. Error code: -32
        CryptoError = -32,
        /// An error with the Random Number Generator occurred. Error code: -33
        RandomError = -33,
        /// A generic IO error has occurred. Error code: -34
        IoError = -34,
        /// There is not enough shares to regenerate a secret: -41
        NotEnoughShares = -41,
        /// The version of the multiple data is inconsistent: -42
        InconsistentVersion = -42
    }
}