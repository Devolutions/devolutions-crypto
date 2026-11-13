namespace Devolutions.Cryptography
{
    /// <summary>
    /// The result of a key encapsulation: the blob to send to the recipient and the local shared secret.
    /// </summary>
    public class EncapsulationResult
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncapsulationResult"/> class.
        /// </summary>
        /// <param name="encapsulatedKey">The encapsulated key to send to the recipient.</param>
        /// <param name="secretKey">The shared secret key.</param>
        public EncapsulationResult(byte[] encapsulatedKey, SecretKey secretKey)
        {
            this.EncapsulatedKey = encapsulatedKey;
            this.SecretKey = secretKey;
        }

        /// <summary>
        /// Gets the encapsulated key to send to the recipient.
        /// </summary>
        public byte[] EncapsulatedKey { get; }

        /// <summary>
        /// Gets the shared secret key, usable with the symmetric methods.
        /// </summary>
        public SecretKey SecretKey { get; }
    }
}
