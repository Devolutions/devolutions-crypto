namespace Devolutions.Cryptography
{
    using System;

    public class KeyPair
    {
        public byte[] PrivateKey { get; set; }

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

        public byte[] PublicKey { get; set; }

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