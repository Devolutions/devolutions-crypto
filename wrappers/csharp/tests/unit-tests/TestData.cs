#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Crypto.Tests
{
    public static class TestData
    {
        public const string Argon2DefaultParametersb64 = "AQAAACAAAAABAAAAABAAAAIAAAACEwAAAAAQAAAAtGY57+B0VqXmHFlvBiIBLg==";

        public const string SigningKeyPairb64 = "DQwFAAEAAQAkrJYWvIXBN4bXndumZVuKQDn2tDkNYC4dLJx3w+1mYEUFIjQa5yMDfXH0K0kiIAOUGSfTsOF6CLb+i0EN5Z7q";

        public const string SigningPublicKeyb64 = "DQwFAAIAAQBFBSI0GucjA31x9CtJIiADlBkn07Dhegi2/otBDeWe6g==";

        public const string SignTesting = "Testing";

        public const string SignedTestingb64 = "DQwGAAAAAQDAwPiQInFO3XNdZjeYUVSzpFrZu/Tfwsf7WZIKNwP6O8v/msm4E4bp7jW/miCWj+P7U5FIqucCh8/QuRURWvkB";

        public const string Base64TestData = "QUJD";

        public const string Base64TestData2 = "QUJDDE";

        public const string StringTestData = "ABC";

        public const string TestPassword = "Key123";

        public const string Base64Url1 = "QWI2Lw";

        public const string Base64Url2 = "QWI2Lzc1";

        public const string Base64Url3 = "___-_w";

        public const string ScryptHash = "$rscrypt$0$CggB$kqMiZ1/rLr/0GAh97TYMO/x3Ppx1lbQPO/OCHC2Qesw=$4J5xGu24Q3YM2Yvvyic3d1/+gLXnBkfeoL33sKEYZwE=$";

        public static readonly byte[] Base64UrlBytes1 = new byte[] { 0x41, 0x62, 0x36, 0x2f };

        public static readonly byte[] Base64UrlBytes2 = new byte[] { 0x41, 0x62, 0x36, 0x2f, 0x37, 0x35 };

        public static readonly byte[] Base64UrlBytes3 = new byte[] { 0xff, 0xff, 0xfe, 0xff };

        public static readonly byte[] Salt = new byte[]
            {
                0x92,
                0xa3,
                0x22,
                0x67,
                0x5f,
                0xeb,
                0x2e,
                0xbf,
                0xf4,
                0x18,
                0x08,
                0x7d,
                0xed,
                0x36,
                0x0c,
                0x3b,
                0xfc,
                0x77,
                0x3e,
                0x9c,
                0x75,
                0x95,
                0xb4,
                0x0f,
                0x3b,
                0xf3,
                0x82,
                0x1c,
                0x2d,
                0x90,
                0x7a,
                0xcc,
            };

        public static readonly byte[] AlicePrivateKey = new byte[]
            {
                0x0d,
                0x0c,
                0x01,
                0x00,
                0x01,
                0x00,
                0x01,
                0x00,
                0x70,
                0x89,
                0x41,
                0x7d,
                0x2b,
                0x5a,
                0x0f,
                0x02,
                0x4e,
                0xfb,
                0x1f,
                0x3c,
                0x7a,
                0x42,
                0x08,
                0xfa,
                0x4a,
                0x57,
                0xa5,
                0xda,
                0xa8,
                0xf9,
                0x47,
                0xdb,
                0xd8,
                0x40,
                0x54,
                0x8b,
                0x49,
                0xd6,
                0xe1,
                0x7a,
            };

        public static readonly byte[] AlicePublicKey = new byte[]
            {
                0x0d,
                0x0c,
                0x01,
                0x00,
                0x02,
                0x00,
                0x01,
                0x00,
                0x86,
                0xef,
                0x7b,
                0x5f,
                0x62,
                0x12,
                0xa0,
                0x39,
                0xa4,
                0x4d,
                0x17,
                0xd8,
                0x04,
                0x1a,
                0x70,
                0x0a,
                0xa9,
                0x0f,
                0xe3,
                0xee,
                0x7f,
                0x90,
                0x28,
                0x0a,
                0xe8,
                0x11,
                0x2b,
                0x16,
                0xb5,
                0xd2,
                0xd6,
                0x77,
            };

        public static readonly byte[] BobPrivateKey = new byte[]
            {
                0x0d,
                0x0c,
                0x01,
                0x00,
                0x01,
                0x00,
                0x01,
                0x00,
                0x50,
                0xd6,
                0x53,
                0x23,
                0x12,
                0xcd,
                0xfd,
                0xa3,
                0xa7,
                0x4c,
                0xac,
                0x56,
                0xcd,
                0xe3,
                0x7a,
                0x69,
                0x40,
                0x1a,
                0xe4,
                0xd1,
                0x5f,
                0x55,
                0xbd,
                0x1f,
                0xaa,
                0x4a,
                0xa8,
                0x76,
                0x30,
                0x37,
                0xf2,
                0x49,
            };

        public static readonly byte[] BobPublicKey = new byte[]
            {
                0x0d,
                0x0c,
                0x01,
                0x00,
                0x02,
                0x00,
                0x01,
                0x00,
                0x39,
                0x04,
                0x34,
                0x68,
                0xf8,
                0x08,
                0xfd,
                0xdc,
                0xe0,
                0xe4,
                0xd2,
                0x3e,
                0x2c,
                0x60,
                0x9b,
                0x23,
                0xab,
                0xf1,
                0x49,
                0xf5,
                0xaf,
                0x1d,
                0x4c,
                0x14,
                0xdd,
                0x03,
                0x81,
                0xe1,
                0x10,
                0x5d,
                0x1e,
                0x39,
            };

        public static readonly byte[] BytesTestData = new byte[] { 0x41, 0x42, 0x43 };

        public static readonly byte[] BytesTestKey = new byte[] { 0x4b, 0x65, 0x79, 0x31, 0x32, 0x33 };

        public static readonly byte[] EncryptedData = new byte[]
            {
                0x0d,
                0x0c,
                0x02,
                0x00,
                0x00,
                0x00,
                0x02,
                0x00,
                0xa4,
                0x24,
                0x87,
                0x8e,
                0xa2,
                0xcb,
                0xd9,
                0x53,
                0xc4,
                0x14,
                0xbf,
                0x9d,
                0x56,
                0x10,
                0x53,
                0x72,
                0x75,
                0xf3,
                0x15,
                0x2e,
                0xfa,
                0x55,
                0x2a,
                0xda,
                0xee,
                0xe7,
                0x7a,
                0xfd,
                0x1d,
                0xf0,
                0xe8,
                0x97,
                0x0b,
                0xc3,
                0x63,
                0x20,
                0x07,
                0x46,
                0xaa,
                0x14,
                0x18,
                0xd6,
                0xd1,
                0x4d,
            };

        public static readonly byte[] TestDeriveBytes = new byte[]
            {
                0x4d,
                0x42,
                0x5d,
                0x3b,
                0x8f,
                0x36,
                0xe4,
                0xff,
                0xb2,
                0x56,
                0xa4,
                0xdc,
                0x7c,
                0x48,
                0x66,
                0x17,
                0x7e,
                0x74,
                0x87,
                0x61,
                0x62,
                0x68,
                0xb1,
                0x2b,
                0x54,
                0x0e,
                0x1a,
                0xf8,
                0x03,
                0xbb,
                0x39,
                0xc4,
            };

        public static readonly byte[] TestDeriveBytes2 = new byte[]
            {
                0xb8,
                0xe8,
                0xea,
                0x5f,
                0xe4,
                0x90,
                0x86,
                0x28,
                0x8d,
                0x98,
                0x67,
                0x6c,
                0xce,
                0x9d,
                0xd4,
                0x21,
                0x2c,
                0x5a,
                0xd0,
                0x9b,
                0x05,
                0x89,
                0xb3,
                0x2f,
                0xd8,
                0x29,
                0x7a,
                0xc0,
                0x67,
                0xb7,
                0xf3,
                0xe2,
            };

        public static readonly byte[] TestHash = new byte[]
            {
                0x0d,
                0x0c,
                0x03,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x10,
                0x27,
                0x00,
                0x00,
                0x36,
                0xf8,
                0x52,
                0x24,
                0x7a,
                0x19,
                0x10,
                0xc5,
                0xa4,
                0x9c,
                0x73,
                0xec,
                0x83,
                0x58,
                0x9b,
                0xea,
                0x63,
                0x3a,
                0xf1,
                0xbf,
                0xf6,
                0xa4,
                0xd8,
                0xe0,
                0x85,
                0xc9,
                0xaa,
                0x9e,
                0xe1,
                0xef,
                0x7f,
                0x60,
                0xf3,
                0x3f,
                0x1b,
                0x6c,
                0x5f,
                0xce,
                0x54,
                0x55,
                0xb8,
                0x73,
                0xc9,
                0xd9,
                0x22,
                0xa0,
                0x24,
                0xca,
                0xe8,
                0xc9,
                0x57,
                0x96,
                0x1b,
                0x3d,
                0xce,
                0x47,
                0xe5,
                0xc3,
                0x39,
                0xe1,
                0x0d,
                0x08,
                0x42,
                0x70,
            };
    }
}
#pragma warning restore SA1600 // Elements should be documented