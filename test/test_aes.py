import unittest
from encryption.aes import encrypt_message, decrypt_message


class TestAES(unittest.TestCase):
    def test_encrypt_decrypt(self):
        passphrase = "this is a test key"
        msg = "this is a test message"

        # encrypt
        ciphertext = encrypt_message(passphrase, msg)
        self.assertNotEqual(ciphertext, None)

        # decrypt
        decrypted = decrypt_message(passphrase, ciphertext)
        self.assertEqual(decrypted, msg)


if __name__ == '__main__':
    unittest.main()
