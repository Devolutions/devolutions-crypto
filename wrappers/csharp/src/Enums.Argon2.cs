namespace Devolutions.Cryptography.Argon2
{
    /// <summary>The Argon2 variant.</summary>
    public enum Variant
    {
        /// <summary>
        /// Argon2 using data-dependent memory access to thwart tradeoff attacks.
        /// Recommended for cryptocurrencies and backend servers.
        /// </summary>
        Argon2d = 0,

        /// <summary>
        /// Argon2 using data-independent memory access to thwart side-channel attacks.
        /// Recommended for password hashing and password-based key
        /// derivation.
        /// </summary>
        Argon2i = 1,

        /// <summary>
        /// Argon2 using hybrid construction.
        /// </summary>
        Argon2id = 2,
    }

    /// <summary>The Argon2 version.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1712:Do not prefix enum values with type name", Justification = "Rust enum")]
    public enum Version
    {
        /// <summary>
        /// Version 0x10.
        /// </summary>
        Version10 = 0x10,

        /// <summary>
        /// Version 0x13 (Recommended).
        /// </summary>
        Version13 = 0x13,
    }
}