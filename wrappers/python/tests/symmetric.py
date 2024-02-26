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


if __name__ == "__main__":
    unittest.main()
