namespace Devolutions.Cryptography
{
    public enum NativeError
    {
        /// <summary>
        /// The provided data has an invalid length. Error code: -1
        /// </summary>
        InvalidLength = -1,

        /// <summary>
        /// The key length is invalid. Error code: -2
        /// </summary>
        InvalidKeyLength = -2,

        /// <summary>
        /// The length of the FFI output buffer is invalid. Error code: -3
        /// </summary>
        InvalidOutputLength = -3,

        /// <summary>
        /// The signature of the data blob does not match 0x0d0c. Error code: -11
        /// </summary>
        InvalidSignature = -11,

        /// <summary>
        /// The MAC is invalid. Error code: -12
        /// </summary>
        InvalidMac = -12,

        /// <summary>
        /// The operation cannot be done with this type. Error code: -13
        /// </summary>
        InvalidDataType = -13,

        /// <summary>
        /// The data type is unknown. Error code: -21
        /// </summary>
        UnknownType = -21,

        /// <summary>
        /// The data subtype is unknown. Error code: -22
        /// </summary>
        UnknownSubtype = -22,

        /// <summary>
        /// The data type version is unknown. Error code: -23
        /// </summary>
        UnknownVersion = -23,

        /// <summary>
        /// The data is invalid. Error code: -24
        /// </summary>
        InvalidData = -24,

        /// <summary>
        /// A null pointer has been passed to the FFI interface. Error code: -31
        /// </summary>
        NullPointer = -31,

        /// <summary>
        /// A cryptographic error occurred. Error code: -32
        /// </summary>
        CryptoError = -32,

        /// <summary>
        /// An error with the Random Number Generator occurred. Error code: -33
        /// </summary>
        RandomError = -33,

        /// <summary>
        /// A generic IO error has occurred. Error code: -34
        /// </summary>
        IoError = -34,

        /// <summary>
        /// There is not enough shares to regenerate a secret: -41
        /// </summary>
        NotEnoughShares = -41,

        /// <summary>
        /// The version of the multiple data is inconsistent: -42
        /// </summary>
        InconsistentVersion = -42,
    }
}