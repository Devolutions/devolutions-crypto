import unittest
import devolutions_crypto
from base64 import b64encode, b64decode
import os

class TestSymmetric(unittest.TestCase):
    def test_symmetric(self):
        key = os.urandom(32)
        plaintext = b'Test plaintext'

        ciphertext = devolutions_crypto.encrypt(plaintext, key)

        self.assertEqual(devolutions_crypto.decrypt(ciphertext, key), plaintext)
    
    def test_symmetric_with_aad(self):
        key = os.urandom(32)
        plaintext = b'Test plaintext'
        aad = b"Test AAD"

        ciphertext = devolutions_crypto.encrypt(plaintext, key, aad)

        self.assertEqual(devolutions_crypto.decrypt(ciphertext, key, aad), plaintext)

        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.decrypt(ciphertext, key)

        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.decrypt(ciphertext, key, aad = b"Wrong AAD")

    def test_symmetric_with_secret_key(self):
        key = devolutions_crypto.generate_secret_key()
        plaintext = b'Test plaintext'

        ciphertext = devolutions_crypto.encrypt_with_secret_key(plaintext, key)

        self.assertEqual(devolutions_crypto.decrypt_with_secret_key(ciphertext, key), plaintext)

    def test_symmetric_with_secret_key_and_aad(self):
        key = devolutions_crypto.generate_secret_key()
        plaintext = b'Test plaintext'
        aad = b"Test AAD"

        ciphertext = devolutions_crypto.encrypt_with_secret_key(plaintext, key, aad)

        self.assertEqual(devolutions_crypto.decrypt_with_secret_key(ciphertext, key, aad), plaintext)

        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.decrypt_with_secret_key(ciphertext, key)

        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.decrypt_with_secret_key(ciphertext, key, aad = b"Wrong AAD")


if __name__ == "__main__":
    unittest.main()
