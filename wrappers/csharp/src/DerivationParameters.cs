namespace Devolutions.Cryptography
{
    using System;

    /// <summary>
    /// Serializable parameters that fully describe a completed key derivation.
    /// Can be stored alongside a user record to re-derive the same key later.
    /// </summary>
    public class DerivationParameters
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DerivationParameters"/> class.
        /// </summary>
        public DerivationParameters(byte[] payload)
        {
            this.Payload = payload;
        }

        /// <summary>
        /// Gets the raw serialized parameters data.
        /// </summary>
        internal byte[] Payload { get; }

        /// <summary>
        /// Gets the raw serialized parameters data as a base64 string.
        /// </summary>
        public string PayloadString => Convert.ToBase64String(this.Payload);

        /// <summary>
        /// Deserialize a <see cref="DerivationParameters"/> from a byte array.
        /// </summary>
        /// <param name="data">The serialized parameters bytes.</param>
        /// <returns>Returns the deserialized <see cref="DerivationParameters"/>.</returns>
        public static DerivationParameters FromByteArray(byte[] data)
        {
            return new DerivationParameters(data);
        }

        /// <summary>
        /// Serialize the <see cref="DerivationParameters"/> to a byte array.
        /// </summary>
        /// <returns>Returns the raw serialized parameters bytes.</returns>
        public byte[] ToByteArray()
        {
            return this.Payload;
        }
    }
}
