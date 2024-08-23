import unittest
from utils import generate_key, encrypt_data, decrypt_data, get_hashed_data, check_hash
from Crypto.Random import get_random_bytes

class TestUtils(unittest.TestCase):

    def test_generate_key(self):
        """Test that the generated key is not None and has the expected length."""
        key = generate_key()
        self.assertIsNotNone(key, "Generated key should not be None.")
        
        # Base64 encoding of 16 bytes results in a 24-character string
        self.assertEqual(len(key), 24, "Generated key should be 24 characters long due to base64 encoding.")

    def test_encrypt_decrypt_data(self):
        """Test that data is correctly encrypted and then decrypted to its original form."""
        key = generate_key()
        data = "This is a test string"
        encrypted_data = encrypt_data(data, key)
        
        self.assertNotEqual(encrypted_data, data, "Encrypted data should not be the same as original data.")
        
        decrypted_data = decrypt_data(encrypted_data, key)
        self.assertEqual(decrypted_data, data, "Decrypted data should match the original data.")

    def test_encrypt_decrypt_with_different_keys(self):
        """Test that decrypting with a different key does not yield the original data."""
        key = generate_key()
        different_key = generate_key()
        data = "This is a test string"
        encrypted_data = encrypt_data(data, key)

        with self.assertRaises(ValueError, msg="Decryption with a different key should raise ValueError due to MAC check failure."):
            decrypt_data(encrypted_data, different_key)

    def test_get_hashed_data(self):
        """Test that the hash of the data is correctly generated and consistent."""
        data = "This is a test string"
        hash_data = get_hashed_data(data)
        
        self.assertIsNotNone(hash_data, "Hashed data should not be None.")
        self.assertNotEqual(hash_data, data, "Hashed data should not be the same as the original data.")
        
        # Hashing the same data should result in the same hash
        hash_data_again = get_hashed_data(data)
        self.assertEqual(hash_data, hash_data_again, "Hash should be consistent for the same data.")

    def test_check_hash_valid(self):
        """Test that check_hash returns True for valid data and hash."""
        data = "This is a test string"
        hash_data = get_hashed_data(data)
        
        self.assertTrue(check_hash(data, hash_data), "Hash check should return True for valid data and hash.")

    def test_check_hash_invalid(self):
        """Test that check_hash returns False for invalid data or hash."""
        data = "This is a test string"
        hash_data = get_hashed_data(data)
        
        invalid_data = "This is a modified string"
        self.assertFalse(check_hash(invalid_data, hash_data), "Hash check should return False for invalid data and hash.")

if __name__ == '__main__':
    unittest.main()
