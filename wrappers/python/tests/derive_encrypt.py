import unittest
import devolutions_crypto


class TestDeriveEncrypt(unittest.TestCase):
    def test_roundtrip_with_password(self):
        plaintext = b"hello world"
        password = b"mypassword"

        blob = devolutions_crypto.derive_encrypt_with_password(plaintext, password)

        self.assertEqual(devolutions_crypto.derive_decrypt_with_password(blob, password), plaintext)

    def test_blob_differs_from_plaintext(self):
        plaintext = b"sensitive data"
        password = b"password123"

        blob = devolutions_crypto.derive_encrypt_with_password(plaintext, password)

        self.assertNotEqual(blob, plaintext)

    def test_each_encryption_uses_random_salt(self):
        plaintext = b"same data"
        password = b"same password"

        blob1 = devolutions_crypto.derive_encrypt_with_password(plaintext, password)
        blob2 = devolutions_crypto.derive_encrypt_with_password(plaintext, password)

        self.assertNotEqual(blob1, blob2)

    def test_wrong_password_fails(self):
        blob = devolutions_crypto.derive_encrypt_with_password(b"secret", b"correct-password")

        with self.assertRaises(devolutions_crypto.DevolutionsCryptoError):
            devolutions_crypto.derive_decrypt_with_password(blob, b"wrong-password")

    def test_roundtrip_with_aad(self):
        plaintext = b"authenticated data"
        password = b"mypassword"
        aad = b"context"

        blob = devolutions_crypto.derive_encrypt_with_password_and_aad(plaintext, password, aad)

        self.assertEqual(
            devolutions_crypto.derive_decrypt_with_password_and_aad(blob, password, aad),
            plaintext,
        )

        # Wrong aad fails to decrypt.
        with self.assertRaises(devolutions_crypto.DevolutionsCryptoError):
            devolutions_crypto.derive_decrypt_with_password_and_aad(blob, password, b"wrong-context")

        # An aad-encrypted blob cannot be decrypted without the aad.
        with self.assertRaises(devolutions_crypto.DevolutionsCryptoError):
            devolutions_crypto.derive_decrypt_with_password(blob, password)


if __name__ == "__main__":
    unittest.main()
