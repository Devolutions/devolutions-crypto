namespace Devolutions.Cryptography
{
    using System;

    /// <summary>
    /// A secret key for symmetric encryption. Should never be sent over an insecure channel or stored unsecurely.
    /// </summary>
    public class SecretKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecretKey"/> class.
        /// </summary>
        public SecretKey(byte[] payload)
        {
            this.Payload = payload;
        }

        /// <summary>
        /// Gets the raw serialized key data.
        /// </summary>
        internal byte[] Payload { get; }

        /// <summary>
        /// Gets the raw key material, without the serialization header. This is the value used as the actual encryption key.
        /// </summary>
        internal byte[] KeyMaterial
        {
            get
            {
                if (this.Payload.Length < 8)
                {
                    throw new InvalidOperationException("Invalid secret key payload: too short to contain header and key material.");
                }

                byte[] result = new byte[this.Payload.Length - 8];
                Array.Copy(this.Payload, 8, result, 0, result.Length);
                return result;
            }
        }

        /// <summary>
        /// Gets the raw serialized key data as a base64 string.
        /// </summary>
        public string PayloadString => Convert.ToBase64String(this.Payload);

        /// <summary>
        /// Deserialize a <see cref="SecretKey"/> from a byte array.
        /// </summary>
        /// <param name="data">The serialized secret key bytes.</param>
        /// <returns>Returns the deserialized <see cref="SecretKey"/>.</returns>
        public static SecretKey FromByteArray(byte[] data)
        {
            return new SecretKey(data);
        }

        /// <summary>
        /// Serialize the <see cref="SecretKey"/> to a byte array.
        /// </summary>
        /// <returns>Returns the raw serialized key bytes.</returns>
        public byte[] ToByteArray()
        {
            return this.Payload;
        }
    }
}
