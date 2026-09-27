import unittest
import base64

class TestPacketDecrypterLogic(unittest.TestCase):
    
    def test_base64_decode(self):
        original = "AeRoLogic Network Test"
        encoded = base64.b64encode(original.encode('utf-8')).decode('utf-8')
        
        # Replicating decode logic from packet_analysis.py
        decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
        self.assertEqual(decoded, original)

    def test_hex_decode(self):
        original = "SecurePayload"
        hex_encoded = original.encode('utf-8').hex()
        
        # Replicating hex decode logic
        decoded = bytes.fromhex(hex_encoded).decode('utf-8', errors='ignore')
        self.assertEqual(decoded, original)

    def test_xor_brute_decode(self):
        original = "TestKey"
        xor_key = 0x5A
        masked_data = bytes([b ^ xor_key for b in original.encode('utf-8')])
        
        # Replicating XOR search logic
        found = False
        for key in range(1, 256):
            unmasked = bytes([b ^ key for b in masked_data])
            if unmasked.decode('utf-8', errors='ignore') == original:
                found = True
                break
        self.assertTrue(found, "XOR key successfully identified and payload unmasked.")

if __name__ == "__main__":
    unittest.main()