namespace Devolutions.Cryptography
{
    using System;

    /// <summary>
    /// Utilitary class to contain both the private and public key.
    /// </summary>
    public class KeyPair
    {
        /// <summary>
        /// The private key.
        /// </summary>
        public byte[] PrivateKey { get; set; }

        /// <summary>
        /// The private key as base 64 string.
        /// </summary>
        public string PrivateKeyString
        {
            get
            {
                if (this.PrivateKey == null)
                {
                    return null;
                }

                return Convert.ToBase64String(this.PrivateKey);
            }
        }

        /// <summary>
        /// The public key.
        /// </summary>
        public byte[] PublicKey { get; set; }

        /// <summary>
        /// The public key key as base 64 string.
        /// </summary>
        public string PublicKeyString
        {
            get
            {
                if (this.PublicKey == null)
                {
                    return null;
                }

                return Convert.ToBase64String(this.PublicKey);
            }
        }
    }
}