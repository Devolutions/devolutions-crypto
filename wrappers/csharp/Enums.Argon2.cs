namespace Devolutions.Cryptography.Argon2
{
    /// <summary>The Argon2 variant.</summary>
    public enum Variant
    {
        /// Argon2 using data-dependent memory access to thwart tradeoff attacks.
        /// Recommended for cryptocurrencies and backend servers.
        Argon2d = 0,

        /// Argon2 using data-independent memory access to thwart side-channel
        /// attacks. Recommended for password hashing and password-based key
        /// derivation.
        Argon2i = 1,

        /// Argon2 using hybrid construction.
        Argon2id = 2
    }

    /// <summary>The Argon2 version.</summary>
    public enum Version
    {
        /// Version 0x10.
        Version10 = 0x10,

        /// Version 0x13 (Recommended).
        Version13 = 0x13,
    }
}