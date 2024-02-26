import unittest
import devolutions_crypto
from base64 import b64encode, b64decode

class TestAsymmetric(unittest.TestCase):
    def test_asymmetric(self):
        keypair = devolutions_crypto.generate_keypair()
        plaintext = b'Test plaintext'

        ciphertext = devolutions_crypto.encrypt_asymmetric(plaintext, keypair.public_key)

        self.assertEqual(devolutions_crypto.decrypt_asymmetric(ciphertext, keypair.private_key), plaintext)

    def test_asymmetric_with_aad(self):
        keypair = devolutions_crypto.generate_keypair()
        plaintext = b'Test plaintext'
        aad = b"Test AAD"

        ciphertext = devolutions_crypto.encrypt_asymmetric(plaintext, keypair.public_key, aad)

        self.assertEqual(devolutions_crypto.decrypt_asymmetric(ciphertext, keypair.private_key, aad), plaintext)

        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.decrypt_asymmetric(ciphertext, keypair.private_key)

        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.decrypt_asymmetric(ciphertext, keypair.private_key, aad = b"Wrong AAD")


if __name__ == "__main__":
    unittest.main()
