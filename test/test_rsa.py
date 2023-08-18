import unittest
from encryption.rsa import generate_key_pair, encrypt_message, decrypt_message


class TestAES(unittest.TestCase):
    def test_encrypt_decrypt(self):
        msg = "this is a test message"

        # get key pair
        private_key_encoded, public_key_encoded = generate_key_pair()
        self.assertNotEqual(private_key_encoded, None)
        self.assertNotEqual(public_key_encoded, None)

        # encrypt
        ciphertext = encrypt_message(public_key_encoded, msg)
        self.assertNotEqual(ciphertext, None)

        # decrypt
        decrypted = decrypt_message(private_key_encoded, ciphertext)
        self.assertEqual(decrypted, msg)


if __name__ == '__main__':
    unittest.main()
