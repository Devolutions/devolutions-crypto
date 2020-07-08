import unittest
import devolutions_crypto
from base64 import b64encode, b64decode

class TestSymmetric(unittest.TestCase):
    def test_symmetric(self):
        keypair = devolutions_crypto.generate_keypair()
        plaintext = b'Test plaintext'

        ciphertext = devolutions_crypto.encrypt_asymmetric(plaintext, keypair.get('public_key'))

        self.assertEqual(devolutions_crypto.decrypt_asymmetric(ciphertext, keypair.get('private_key')), plaintext)


if __name__ == "__main__":
    unittest.main()
