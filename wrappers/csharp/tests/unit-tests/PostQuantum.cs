#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Crypto.Tests
{
    using System;

    using Devolutions.Cryptography;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class PostQuantum
    {
        // Fixed X-Wing (KeyVersion.V2) private key shared with the other conformity suites.
        private const string XWingPrivateKey = "DQwBAAEAAgA1nERi4Of6p1Sg60NSw98tDx4OuBZtVR+CpVe+n1VDLg==";

        [TestMethod]
        public void GenerateKeyPairV2Sizes()
        {
            KeyPair keyPair = Managed.GenerateKeyPair(KeyVersion.V2);
            Assert.AreEqual(40, keyPair.PrivateKey!.Length);
            Assert.AreEqual(1224, keyPair.PublicKey!.Length);
        }

        [TestMethod]
        public void GenerateKeyPairV1Sizes()
        {
            KeyPair keyPair = Managed.GenerateKeyPair(KeyVersion.V1);
            Assert.AreEqual(40, keyPair.PrivateKey!.Length);
            Assert.AreEqual(40, keyPair.PublicKey!.Length);
        }

        [TestMethod]
        public void EncryptDecryptAsymmetricV3()
        {
            byte[] data = Utils.StringToUtf8ByteArray("This is some test data")!;
            KeyPair keyPair = Managed.GenerateKeyPair(KeyVersion.V2);

            byte[] encrypted = Managed.EncryptAsymmetric(data, keyPair.PublicKey!, version: CipherTextVersion.V3)!;
            byte[] decrypted = Managed.DecryptAsymmetric(encrypted, keyPair.PrivateKey!)!;

            Assert.AreEqual(8 + 1120 + 24 + data.Length + 16, encrypted.Length);
            CollectionAssert.AreEqual(data, decrypted);
        }

        [TestMethod]
        public void EncryptDecryptAsymmetricV3Aad()
        {
            byte[] data = Utils.StringToUtf8ByteArray("This is some test data")!;
            byte[] aad = Utils.StringToUtf8ByteArray("This is some public data")!;
            KeyPair keyPair = Managed.GenerateKeyPair(KeyVersion.V2);

            byte[] encrypted = Managed.EncryptAsymmetric(data, keyPair.PublicKey!, aad, CipherTextVersion.V3)!;

            CollectionAssert.AreEqual(data, Managed.DecryptAsymmetric(encrypted, keyPair.PrivateKey!, aad)!);
            Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.DecryptAsymmetric(encrypted, keyPair.PrivateKey!));
        }

        [TestMethod]
        public void EncryptAsymmetricV3RejectsV1Key()
        {
            byte[] data = Utils.StringToUtf8ByteArray("This is some test data")!;
            KeyPair v1 = Managed.GenerateKeyPair(KeyVersion.V1);

            Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.EncryptAsymmetric(data, v1.PublicKey!, version: CipherTextVersion.V3));
        }

        [TestMethod]
        public void DecryptAsymmetricV3WrongKey()
        {
            byte[] data = Utils.StringToUtf8ByteArray("This is some test data")!;
            KeyPair keyPair = Managed.GenerateKeyPair(KeyVersion.V2);
            KeyPair other = Managed.GenerateKeyPair(KeyVersion.V2);
            byte[] encrypted = Managed.EncryptAsymmetric(data, keyPair.PublicKey!, version: CipherTextVersion.V3)!;

            Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.DecryptAsymmetric(encrypted, other.PrivateKey!));
        }

        [TestMethod]
        public void MixKeyExchangeRejectsV2()
        {
            KeyPair v1 = Managed.GenerateKeyPair(KeyVersion.V1);
            KeyPair v2 = Managed.GenerateKeyPair(KeyVersion.V2);

            Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.MixKeyExchange(v2.PrivateKey, v1.PublicKey));
        }

        [TestMethod]
        public void EncapsulateDecapsulate()
        {
            KeyPair keyPair = Managed.GenerateKeyPair(KeyVersion.V2);

            EncapsulationResult result = Managed.Encapsulate(keyPair.PublicKey!);
            SecretKey recovered = Managed.Decapsulate(keyPair.PrivateKey!, result.EncapsulatedKey);

            Assert.AreEqual(1128, result.EncapsulatedKey.Length);
            CollectionAssert.AreEqual(result.SecretKey.ToByteArray(), recovered.ToByteArray());
        }

        [TestMethod]
        public void DecapsulateWrongKeyGivesDifferentSecret()
        {
            KeyPair keyPair = Managed.GenerateKeyPair(KeyVersion.V2);
            KeyPair other = Managed.GenerateKeyPair(KeyVersion.V2);

            EncapsulationResult result = Managed.Encapsulate(keyPair.PublicKey!, KeyEncapsulationVersion.V1);
            SecretKey wrong = Managed.Decapsulate(other.PrivateKey!, result.EncapsulatedKey);

            CollectionAssert.AreNotEqual(result.SecretKey.ToByteArray(), wrong.ToByteArray());
        }

        [TestMethod]
        public void EncapsulateRejectsV1Key()
        {
            KeyPair v1 = Managed.GenerateKeyPair(KeyVersion.V1);

            Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.Encapsulate(v1.PublicKey!));
        }

        [TestMethod]
        public void SecretKeyUsableForSymmetricEncryption()
        {
            KeyPair keyPair = Managed.GenerateKeyPair(KeyVersion.V2);
            EncapsulationResult result = Managed.Encapsulate(keyPair.PublicKey!);
            SecretKey recovered = Managed.Decapsulate(keyPair.PrivateKey!, result.EncapsulatedKey);
            byte[] data = Utils.StringToUtf8ByteArray("symmetric")!;

            byte[] encrypted = Managed.Encrypt(data, result.SecretKey)!;

            CollectionAssert.AreEqual(data, Managed.Decrypt(encrypted, recovered)!);
        }

        [TestMethod]
        public void DecryptAsymmetricV3Conformity()
        {
            byte[] privateKey = Utils.Base64StringToByteArray(XWingPrivateKey)!;

            byte[] plain = Managed.DecryptAsymmetric(
                Utils.Base64StringToByteArray("DQwCAAIAAwCm2YjCoBofihIBaK5pfKKOfY0Ijhhvv+X8fw9bOWk/6TdrsxZBU9bucUBY37Ot1IuMGwBUU+eV5MQz/rTG5NoBai2licmRGBL/EJePhCPg3rgDtOajBszyyOkVVEHt4C+uznm8pJCaiw+zcG3E2pwLBRakUuUhqzHxolzVxRdZ8BaQUhNZSExDB7us3BoEhyiGpkXqKb8JWWrexzWRU/1p/ie6oP+lPG/uHK9ifAZ7k/pOty0lnIaH7R6XQ8tffM6kvyA2Cp7QHqzmGWUct8lKxy4BI7wRzNjpmIbhyHRwgZU5svTiHcccvFIYEqcZoU9gY9zBps9bkJIVK4v9AIlPtY1Ay55kE3Ze5gtHxBEvo1UaXT1+EOmOolqCqIv9Q8sbJIgFhqfkpoX3zy395FfI3C5mgqzTtW+xBOdpzxtnE3u3+M9ModNg4j6cMu6F242TFFJABdKk1CAV+jZ4WeBqt8c3VCnJGvJWGUpM8E6x3UL/C5tsDR7Ifzf39zoYGjEuo6pL9RFfA/VV1iGDFBdRmeVmoGnX0RME5epUuSET/ooymu4Vqn5INi+RTy3nIJwcyeSHEBlMYC0xVWi/veTKkoYfI6qxSYI8oxJXM8uSuZnB7TeKLshMOmt3jFM6bSyarAPlgMkbGDH+zXWe478Po4UcveequOsNABECYNET7fq6J/3ovfZ+6lMBIi2Hl2IMA5Ii/WXAv4N9ihUppFgYdPXooAOaYFoan8ntZKT+88L+s6hzUce9AhTjl+Ts2nWmdowo3rc/sGbH7LqllvGEBVohanBT8Tjy+4Q+zeN6xVpQIW3qcbeI2EE91uRrkVJwTKarB2TEYuTyys2Q3PLUX7/WUj99XBqZfOUEB9Na1F6JgPIL1+PL4Rfe5vSZySsdQi6qk+0bpd9tcauiUQokhzKiBZeLIi9VRimFpU0Qng3NmbopOKPTIBekowLhsyZgrFCqEANdOc8Jhy/OrssharUIu0mNZXgoFfJHn6kmsXgJejQikBRwUq/eUXqoz+k/ddcidKkKlJ1Mr5i7nzMPgODX8/WK229/qsIXq/cGZM9844fgeEcSkQQN9CPwbkw2k/dgWf28xfKGzMAzWpSnUwkC7toubDtYWrMoQWkpTN/nhMbAtTDBn8xrdMu5gkpERf6EeN1QURgje6dx10KpniC6/Vy7Zgg7lmn6h9o3PVpWv4oSlr3YObnUM8UgDsiRommWcBdJ8axl4/yvfeEa882DRJUAWU6nZKyunm1TgSrtFevb/72kJidpNQwmfXmy3gDC/rSXcsmnFSMGdc7a40dNFsmDZVui5386GsQk/Uta6h1zsZmqoW7AuaSDqhNo44Gbr5b57zjSwP9okkPvUVi2avFVIZsZFBl7FlWLVwb0d6HEzWVX93ZRxFosUBo5aS+btaT4YF9z++4xjST83whVU3o4TOQTq9mgAV/91JRB5+fT6P2wkOuuUuPe6gemH50LV0cYbxAHECt4OggFaAjHodoPqW0VRkU74M3xzZbKusiQv0YHDWsvqRzUuJ46XVWl+ZW2jVulTgmaSg/s"),
                privateKey)!;
            Assert.AreEqual("testdata", Utils.ByteArrayToUtf8String(plain));

            byte[] plainAad = Managed.DecryptAsymmetric(
                Utils.Base64StringToByteArray("DQwCAAIAAwCY+aboyvWcG4QDu2lQfA8io0hemIghqdHjzt2b/nUpa3p9hMmnquY2zaMaugi3Lq1DyQuiau7BgDbv2Ew0fvumqvNi6EtmOOTgTp4cyCFQxBxq1dw4k1o1kdGm4I7W1h+NMnJfQ5tPjE2xRDKgDlkoOqdWv9AJmY2jFBQ65x4tVOl+a2VyicbFUNz6wpjN1vytLaWe3KZhckYt/yx6bZOJ13U7weaGezcGJwbcPTKUALSGqe6apJbOzVYxByq33j5652Cc8uL8USEJJ0pgvAYsukvgAtqycnz9wOi7dtmmmBa/2Ubzyo5U/5O6LBqHjv1irvQ3YIqn4XRXaXJ4Odik70xlG0LsiTBymr0SgGMQq0yIzoxfDOCyM6O5rBDpqlFKs+KdyN/luU+FzvJuSfR+WechpzJKW7pT5iKB/UQefXb5Dr8IMmRH7ca90Miq30yk+2lYnhI7i/K9kDoh/rM6j1xfk/j4UMWWVLnbAK3ZRbioCYF4H47ya1yQqYdrj3ZpiNLcLy2Oj8suAeVDyJFqIwDHFlsCfrgSnr1OJ5kWRkb5y/BW0S/33MTJpewAc7RztE/Dv5UfpY15GjVlY5LRj8L3oXmfF8qOvKAnzoo4pxqZMnKXCZkbyAf8FRYEF2e/J29KrzWBBVTAQMhMNqaHMw55Q2U8Cv5/eioPw1YmHYDU9E7+xmTM0KLK1/fcRQCnmFY8nVs3FRL1DdkIowjSWV5OwiWrHKYcMth5Kc556XI6VN46zOKYCEdjRwNuz9o3bCTCTeHmVFYspcwey3dRkzlKKJpmg69kQlM+5V/Ts+PY4yQ0eY0yx/vcZAmdp3H3t6LddHiOSd811z9SlsGK0YvbDgx8iRjEPFnwRlm6aly1fBYXWlk3JxvzOJCYwTqo2Q3xi4wMRA6FVwDRmDlazMSZ/qu+l5QbkXqfXAK4dCZbxksr9IXUINDcakLK3laD+iTBw+PSRfb0nyKkOoq+KbBZHRI94cGEm1Pn0Q88gPME2X02lfiMNe3fPwGPMlf6D0Ovykl0DI+IvahRqBE5h4LhneHD9j6PKuJzSy83EKsS+uLQ7nuYGoNpZFu/8wNEdkylVpCvY4SRVmAcmzBcbvv8V1NZek6sYY8BtKY7cCeyIr9wq9MMw3ZypMufpE1n5wIaQ+Y9Smgc9Vb8eV5Gsjsaam6mhzwJ38HqKmFBWVf886MhE4OuuBUEI76EeSXf3TAG+MIFqoKwfqJsLmtznDNBGDbmqC9g1J6jTplMH0zPl95LNL0SMS6+ObnVPHxJ/QBExSMbIvW7yTQ03dX2WawBbdNTee41Ev6cGQsXWnMjnOfAlIfwj1z6ZB2umYeAsRtju+0idLmqARnLnVDp2oIn4nAckkT8qoOMOVw81xvL5UYoepJREOr/k3X3tfLtFeaY4VtBrpGvUIo37hWYiDHP/vqdR7yzrkx3O3b/UVsV3JLGTIjf/brGErTsNmly+IAkR4MzwbQfezCxgCcpalHS/3GWUTWf3ureWok3q7aVj8slI7zmfFMpgdLFvVekdKUCVsF/1BMhB6gwfWuV"),
                privateKey,
                Utils.StringToUtf8ByteArray("this is some public data"))!;
            Assert.AreEqual("testdata", Utils.ByteArrayToUtf8String(plainAad));
        }

        [TestMethod]
        public void DecapsulateConformity()
        {
            byte[] privateKey = Utils.Base64StringToByteArray(XWingPrivateKey)!;

            SecretKey secret = Managed.Decapsulate(
                privateKey,
                Utils.Base64StringToByteArray("DQwKAAAAAQAdAidiTcgaZ0lFtIEr7TWNrzDq7XkFBWLSDqU+tWi68zmUXyMMxwXPSwYuX0QLAhArzNyMJXqo88zrYR+AfAeeeBVpRLq4naSDQ12j0d3gsNFbhBRzCbaa/WL92DwNQSZoA3Z1bSToRkxepJW7kcqTHs6DfFn9WAWBpU8Qul3iHWfiFqY0/xNdzMfb0H61qaLlB9C762rXwqKw5jGF1XOih6q2jwZjKOp7bZK+JNXMTb9X5BqJl/spn3FKLIhOLp85M26hDdJM1THqNCkm8/xYWVA6alkdfL9ZGE1IxJv9i8B5rW0qK7sG54a+ZuGnSaf3TZiSSR1D519WHttp+rlI/yNNWXxsOcmZmOEKw4DX2XQS5IQ9S1wflnaBwRVyBIfMUILnKSWZ0EwlgCs6XKnFy/5NqRNyZbDSAcJ+ROA/8H7yMrYQV0ilwl9mXAx9Ip9AHYsrrjC2IM3iWUBR6gqM7bwmBVb/eN51WwSXK8Vcy4FPeeii6VvFND/rEiiERhmRBRFhDNYmf5tARfBgccPw62GO56IjkBuyZhoUZ6DB8Uy8nVxcoe0hpN6fiCW10S8cBWdKtyJObkl9oqRbxmB21bKSJS/yz3owxqivTSaaLAT5HQy6FnPFYoOoG57Vp/WEIU00C5GwuAs6MUbuBBiZtjeJMRkV/HJidgH1WPIx0Xs7EKf/N4kkVok2D9ZdL9jSbLV69QR5SeW8M2U9B+1oqZghXpI4en20WEvGxEJ1ALCd2VlQqK76vLZpXX0DSlhMv14VzR7fUiZiurpH8S/tbieCMijdeWt9a5lnWTzWE0IVgALHLH2T82R6RJSIbBE7EwWziYO3Vm0Tus3iY+GxzSRqaBHc0oCsbFDFG3BkWF7gWOeTElnz7taRRqKnolN4VWfPRQ6Glmq8ml/83HTQFJfW7yI5jKp+I9vSCZ/tAcOTaneUDZ6cveDfPIWnLsSld2t/1MtXlzbRHGqGfe3nyU94TU7WDeFGcgL+EykMu58RVxVT5yefqy6kTlnkUWqr7j2EwrayzT0D5d4dvzJp38SXDsHL2/W2bsmv7WipnjFAp8xh0gNd5AGysTf+xJ8+Qv6D/aQF8JgEvVn+E7i5JcAWFIHelVupk6JJPX7KNalqN3LqBwuFm2gb7rTkdGWGoFw23+1NeyfuLPWSPq79NuzKw/5PqhQWlwDxOC88aF8lYLB3QrT8AcF/2ciwaT2j33YpRdhkFVbPrwNUPFsVV+LA4NplDywB81mABsfS3JSHhiXPLAKZhHV56qmM2gFG5dicrHOm6k7s3mDAfH/LUNrHgUs7ihYr3BzCocIfq//1RDf9NmJWj9rKbj3NpeAGnkMD68W82xv5SAYpkC6E5mZMJD1O6CBmgnPkLc6/YNxWfE/O37o18gTvjpYZourUxsX1BwAnoLjz+nptQJqJHzJeeA/GqaaoP+8F+LyEAxKFBIFD/XYK4xJ6N3v4OtforFb9QtvwCoMKnZvbeMEd")!);

            // The serialized secret key is an 8-byte header followed by the 32 key bytes.
            byte[] raw = new byte[32];
            Array.Copy(secret.ToByteArray(), 8, raw, 0, 32);
            Assert.AreEqual("hqnsrwF5qEgJsI0G4aURCcbbsshKl7Z590eicp0ArtA=", Convert.ToBase64String(raw));
        }
    }
}
