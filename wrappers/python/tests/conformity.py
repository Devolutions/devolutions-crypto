import unittest
import devolutions_crypto
from base64 import b64encode, b64decode

class TestComformity(unittest.TestCase):
    def test_derive_pbkdf2(self):
        self.assertEqual(devolutions_crypto.derive_key_pbkdf2(b'testpassword'), b64decode(b'ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8='))
        self.assertEqual(devolutions_crypto.derive_key_pbkdf2(b'testPa$$', None, 100), b64decode(b'ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4='))
        self.assertEqual(devolutions_crypto.derive_key_pbkdf2(b'testPa$$', b64decode(b'tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA='), 100), b64decode(b'ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI='))

    def test_decrypt_v1(self):
        key = b64decode(b'ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
        ciphertext = b64decode(b'DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==')

        self.assertEqual(devolutions_crypto.decrypt(ciphertext, key), b'test Ciph3rtext~')
    
    def test_decrypt_v1_with_aad(self):
        key = b64decode(b'ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
        aad = b"this is some public data"
        ciphertext = b64decode(b'DQwCAAEAAQCeKfbTqYjfVCEPEiAJjiypBstPmZz0AnpliZKoR+WXTKdj2f/4ops0++dDBVZ+XdyE1KfqxViWVc9djy/HSCcPR4nDehtNI69heGCIFudXfQ==')

        self.assertEqual(devolutions_crypto.decrypt(ciphertext, key, aad=aad), b'test Ciph3rtext~')

    def test_decrypt_v2(self):
        key = b64decode(b'ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
        ciphertext = b64decode(b'DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=')

        self.assertEqual(devolutions_crypto.decrypt(ciphertext, key), b'test Ciph3rtext~2')

    def test_decrypt_v2_with_aad(self):
        key = b64decode(b'ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
        aad = b"this is some public data"
        ciphertext = b64decode(b'DQwCAAEAAgA9bh989dao0Pvaz1NpJTI5m7M4br2qVjZtFwXXoXZOlkCjtqU/uif4pbNCcpEodzeP4YG1QvfKVQ==')

        self.assertEqual(devolutions_crypto.decrypt(ciphertext, key, aad=aad), b'test Ciph3rtext~')

    def test_asymmetric_v2(self):
        private_key = b64decode(b'DQwBAAEAAQAAwQ3oJvU6bq2iZlJwAzvbmqJczNrFoeWPeIyJP9SSbQ==')
        ciphertext = b64decode(b'DQwCAAIAAgCIG9L2MTiumytn7H/p5I3aGVdhV3WUL4i8nIeMWIJ1YRbNQ6lEiQDAyfYhbs6gg1cD7+5Ft2Q5cm7ArsGfiFYWnscm1y7a8tAGfjFFTonzrg==')
        
        self.assertEqual(devolutions_crypto.decrypt_asymmetric(ciphertext, private_key), b"testdata")

    def test_asymmetric_v2_with_aad(self):
        private_key = b64decode(b'DQwBAAEAAQC9qf9UY1ovL/48ALGHL9SLVpVozbdjYsw0EPerUl3zYA==')
        ciphertext = b64decode(b'DQwCAAIAAgB1u62xYeyppWf83QdWwbwGUt5QuiAFZr+hIiFEvMRbXiNCE3RMBNbmgQkLr/vME0BeQa+uUTXZARvJcyNXHyAE4tSdw6o/psU/kw/Z/FbsPw==')
        aad = b"this is some public data"
        
        self.assertEqual(devolutions_crypto.decrypt_asymmetric(ciphertext, private_key, aad=aad), b"testdata")

    def test_signature(self):
        signature = b64decode(b'DQwGAAAAAQD82uRk4sFC8vEni6pDNw/vOdN1IEDg9cAVfprWJZ/JBls9Gi61cUt5u6uBJtseNGZFT7qKLvp4NUZrAOL8FH0K')
        public_key = b64decode(b'DQwFAAIAAQDeEvwlEigK5AXoTorhmlKP6+mbiUU2rYrVQ25JQ5xang==')
        self.assertTrue(devolutions_crypto.verify_signature(b"this is a test", public_key, signature))
        self.assertFalse(devolutions_crypto.verify_signature(b"this is wrong", public_key, signature))

if __name__ == "__main__":
    unittest.main()
