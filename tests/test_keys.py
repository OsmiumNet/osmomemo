import unittest

from osmomemo import XKeyPair
from osmomemo import EdKeyPair

class TestKeys(unittest.TestCase):
    def test_generating(self):
        xpair = XKeyPair.generate()
        edpair = EdKeyPair.generate()

        self.assertIsInstance(xpair, XKeyPair)
        self.assertIsInstance(edpair, EdKeyPair)

