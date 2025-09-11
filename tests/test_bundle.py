import unittest

from osmomemo import XKeyPair
from osmomemo import EdKeyPair
from osmomemo import OmemoBundle

class TestOmemo(unittest.TestCase):
    def test_fingerprint(self):
        bundle = OmemoBundle(
            90909090,
            EdKeyPair.generate(),
            XKeyPair.generate(),
            {
                "0": XKeyPair.generate(),
                "1": XKeyPair.generate(),
                "2": XKeyPair.generate(),
            }
        )

        # Bob
        indentity_fingerprint = bundle.get_indentity_hex_fingerprint()
        b64_public_indentity = bundle.get_indentity().get_base64_public_key()

        # Alice
        public_indentity = EdKeyPair.base64_to_public_key(b64_public_indentity)
        public_indentity_bytes = EdKeyPair.public_key_to_bytes(public_indentity)

        fingerprint = OmemoBundle.public_key_to_hex_fingerprint(public_indentity_bytes)

        self.assertEqual(indentity_fingerprint, fingerprint)






       

