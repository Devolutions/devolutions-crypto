namespace Devolutions.Cryptography.Signature
{
    /// <summary>
    /// Class used to represent a signing public key from Devolutions Crypto.
    /// </summary>
    public class SigningPublicKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SigningPublicKey"/> class.
        /// </summary>
        public SigningPublicKey()
        {
        }

        /// <summary>
        /// Gets or sets the raw public key data.
        /// </summary>
        internal byte[] Payload { get; set; }

        /// <summary>
        /// Deserialize the SigningPublicKey class from a little endian byte array.
        /// </summary>
        /// <param name="data">The data to deserialize.</param>
        /// <returns>Returns the deserialized parameters.</returns>
        public static SigningPublicKey FromByteArray(byte[] data)
        {
            SigningPublicKey publicKey = new SigningPublicKey();
            publicKey.Payload = data;

            return publicKey;
        }

        /// <summary>
        /// Serialize the SigningPublicKey class to a little endian byte array.
        /// </summary>
        /// <returns>Returns SigningPublicKey class to a little endian byte array.</returns>
        public byte[] ToByteArray()
        {
            return this.Payload;
        }
    }
}