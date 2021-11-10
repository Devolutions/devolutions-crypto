namespace Devolutions.Cryptography.Signature
{
    using System;

    /// <summary>
    /// Class used to represent a signing key pair from Devolutions Crypto.
    /// </summary>
    public class SigningKeyPair
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SigningKeyPair"/> class.
        /// </summary>
        public SigningKeyPair()
        {
        }

        internal byte[] Payload { get; set; }

        /// <summary>
        /// Deserialize the SigningKeyPair class from a little endian byte array.
        /// </summary>
        /// <param name="data">The data to deserialize.</param>
        /// <returns>Returns the deserialized parameters.</returns>
        public static SigningKeyPair FromByteArray(byte[] data)
        {
            SigningKeyPair keypair = new SigningKeyPair();
            keypair.Payload = data;

            return keypair;
        }

        /// <summary>
        /// Extract the public key from the key pair.
        /// </summary>
        /// <returns>Returns the extracted public key.</returns>
        public SigningPublicKey GetPublicKey()
        {
            byte[] publicKeyNative = new byte[Native.GetSigningPublicKeySize(this.Payload, (UIntPtr)this.Payload.Length)];

            long res = Native.GetSigningPublicKey(this.Payload, (UIntPtr)this.Payload.Length, publicKeyNative, (UIntPtr)publicKeyNative.Length);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return SigningPublicKey.FromByteArray(publicKeyNative);
        }

        /// <summary>
        /// Serialize the SigningKeyPair class to a little endian byte array.
        /// </summary>
        /// <returns>Returns SigningKeyPair class to a little endian byte array.</returns>
        public byte[] ToByteArray()
        {
            return this.Payload;
        }
    }
}