import unittest
import devolutions_crypto


class TestPasswordHash(unittest.TestCase):
    def test_hash_password_default(self):
        """Default version uses Argon2id (V2)."""
        password = b'my_secure_password'
        hash_value = devolutions_crypto.hash_password(password)
        self.assertTrue(devolutions_crypto.verify_password(password, hash_value))

    def test_hash_password_v1_pbkdf2(self):
        """Explicit V1 uses PBKDF2-SHA256."""
        password = b'my_secure_password'
        hash_value = devolutions_crypto.hash_password(password, version=1)
        self.assertTrue(devolutions_crypto.verify_password(password, hash_value))

    def test_verify_wrong_password(self):
        """verify_password returns False for incorrect password."""
        hash_value = devolutions_crypto.hash_password(b'correct_password')
        self.assertFalse(devolutions_crypto.verify_password(b'wrong_password', hash_value))

    def test_hash_is_non_deterministic(self):
        """Two hashes of the same password are different (random salt)."""
        password = b'same_password'
        hash1 = devolutions_crypto.hash_password(password)
        hash2 = devolutions_crypto.hash_password(password)
        self.assertNotEqual(hash1, hash2)
        self.assertTrue(devolutions_crypto.verify_password(password, hash1))
        self.assertTrue(devolutions_crypto.verify_password(password, hash2))

    def test_hash_password_with_argon2_params(self):
        """hash_password_with_params works with default Argon2id parameters."""
        password = b'my_secure_password'
        params = devolutions_crypto.get_argon2_derivation_parameters()
        hash_value = devolutions_crypto.hash_password_with_params(password, params)
        self.assertTrue(devolutions_crypto.verify_password(password, hash_value))
        self.assertFalse(devolutions_crypto.verify_password(b'wrong_password', hash_value))

    def test_hash_password_with_pbkdf2_params(self):
        """hash_password_with_params works with PBKDF2 parameters."""
        password = b'my_secure_password'
        params = devolutions_crypto.get_pbkdf2_derivation_parameters(iterations=10000)
        hash_value = devolutions_crypto.hash_password_with_params(password, params)
        self.assertTrue(devolutions_crypto.verify_password(password, hash_value))
        self.assertFalse(devolutions_crypto.verify_password(b'wrong_password', hash_value))

    def test_verify_invalid_hash_raises(self):
        """verify_password raises on invalid/truncated hash bytes."""
        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.verify_password(b'password', b'not_a_valid_hash')

    def test_hash_password_unknown_version_raises(self):
        """hash_password raises on an unknown version number."""
        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.hash_password(b'password', version=999)

    def test_hash_password_with_params_invalid_params_raises(self):
        """hash_password_with_params raises on invalid DerivationParameters bytes."""
        with self.assertRaises(devolutions_crypto.DevolutionsCryptoException):
            devolutions_crypto.hash_password_with_params(b'password', b'invalid_params')


if __name__ == "__main__":
    unittest.main()
