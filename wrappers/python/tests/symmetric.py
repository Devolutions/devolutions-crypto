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


if __name__ == "__main__":
    unittest.main()
