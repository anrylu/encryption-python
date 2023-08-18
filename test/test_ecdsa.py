import unittest
from encryption.eddsa import generate_key_pair, sign, verify


class TestEDDSA(unittest.TestCase):
    def test_sign_verify(self):
        msg = "this is a test message"

        # get key pair
        private_key_encoded, public_key_encoded = generate_key_pair()
        self.assertNotEqual(private_key_encoded, None)
        self.assertNotEqual(public_key_encoded, None)

        # sign
        signature_encoded = sign(private_key_encoded, msg)
        self.assertNotEqual(signature_encoded, None)

        # decrypt
        is_valid = verify(public_key_encoded, msg, signature_encoded)
        self.assertEqual(is_valid, True)


if __name__ == '__main__':
    unittest.main()
