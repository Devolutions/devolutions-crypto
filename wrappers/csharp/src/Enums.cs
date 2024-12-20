namespace Devolutions.Cryptography
{
    using System;

    /// <summary>
    /// Devolutions Crypto Data Type.
    /// </summary>
    public enum DataType
    {
        /// <summary>
        /// Key
        /// </summary>
        Key = 1,

        /// <summary>
        /// Cipher
        /// </summary>
        Cipher = 2,

        /// <summary>
        /// Password Hash
        /// </summary>
        PasswordHash = 3,

        /// <summary>
        /// Password Hash
        /// </summary>
        [Obsolete("This value has been deprecated. Use DataType.PasswordHash instead.")]
        Hash = 3,

        /// <summary>
        /// A wrapped share. Used for secret sharing scheme.
        /// </summary>
        Share = 4,

        /// <summary>
        /// A wrapped key used to sign data.
        /// </summary>
        SigningKey = 5,

        /// <summary>
        /// A wrapped signature
        /// </summary>
        Signature = 6,

        /// <summary>
        /// TODO
        /// </summary>
        OnlineCiphertext = 7
    }

    /// <summary>
    /// Devolutions Crypto Cipher Version.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "V2_5 is not version 25")]
    public enum CipherTextVersion
    {
        /// <summary>
        /// This is the latest version. (Currently XChaCha20Poly1305)
        /// </summary>
        Latest = 0,

        /// <summary>
        /// Aes256CbcHmacSha256
        /// </summary>
        V1 = 1,

        /// <summary>
        /// XChaCha20Poly1305
        /// </summary>
        V2 = 2,

        /// <summary>
        /// XChaCha20Poly1305 with DeriveKey length fix
        /// </summary>
        V2_5 = 2,
    }

    /// <summary>
    /// Devolutions Crypto Signature Version.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "V2_5 is not version 25")]
    public enum SignatureVersion
    {
        /// <summary>
        /// This is the latest version. (Currently ed25519)
        /// </summary>
        Latest = 0,

        /// <summary>
        /// ed25519
        /// </summary>
        V1 = 1,
    }

    /// <summary>
    /// Enum containing the different error codes on the managed side.
    /// </summary>
    public enum ManagedError
    {
        /// <summary>
        /// Error when an invalid parameter was received. (Ex: Null Encryption Key)
        /// </summary>
        InvalidParameter,

        /// <summary>
        /// Error when the devolutions crypto native library version doesn't match the managed version.
        /// </summary>
        IncompatibleVersion,

        /// <summary>
        /// Error when the native library cannot be loaded
        /// </summery>
        NativeLibraryLoad,

        /// <summary>
        /// Error when the stream cannot be seek.
        /// </summary>
        CanNotSeekStream,

        /// <summary>
        /// Error when the stream cannot be read.
        /// </summary>
        CanNotReadStream,

        /// <summary>
        /// Unknown error.
        /// </summary>
        Error,
    }
}