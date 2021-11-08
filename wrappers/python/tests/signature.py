import unittest
import devolutions_crypto
from base64 import b64encode, b64decode

class TestSymmetric(unittest.TestCase):
    def test_signature(self):
        data = b"this is some test data"
        keypair = devolutions_crypto.generate_signing_keypair()
        public = devolutions_crypto.get_signing_public_key(keypair)

        signature = devolutions_crypto.sign(data, keypair)

        self.assertTrue(devolutions_crypto.verify_signature(data, public, signature))
        self.assertFalse(devolutions_crypto.verify_signature(b"this data is wrong", public, signature))


if __name__ == "__main__":
    unittest.main()
