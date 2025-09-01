import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  

from osmomemo import XKeyPair
from osmomemo import EdKeyPair

class TestKeys(unittest.TestCase):
    def test_generating(self):
        xpair = XKeyPair.generate()
        edpair = EdKeyPair.generate()

        self.assertIsInstance(xpair, XKeyPair)
        self.assertIsInstance(edpair, EdKeyPair)

        self.assertIsInstance(xpair.get_private_key(), X25519PrivateKey)
        self.assertIsInstance(xpair.get_public_key(), X25519PublicKey)
        self.assertIsInstance(edpair.get_private_key(), Ed25519PrivateKey)
        self.assertIsInstance(edpair.get_public_key(), Ed25519PublicKey)

    def test_converting(self):
        edpair = EdKeyPair.generate()

        self.assertIsInstance(edpair.get_x_private_key(), X25519PrivateKey)
        self.assertIsInstance(edpair.get_x_public_key(), X25519PublicKey)


        xpair = XKeyPair(edpair.get_x_private_key())

        self.assertEqual(xpair.get_public_key(), edpair.get_x_public_key())
