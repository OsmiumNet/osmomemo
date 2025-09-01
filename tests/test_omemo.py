import unittest

import base64

from osmomemo import Omemo
from osmomemo import OmemoBundle
from osmomemo import XKeyPair
from osmomemo import EdKeyPair

class TestOmemo(unittest.TestCase):
    def test_init(self):
        bundle_a = OmemoBundle(
            EdKeyPair.generate(),
            XKeyPair.generate(),
            {
                "0": XKeyPair.generate(),
                "1": XKeyPair.generate(),
                "2": XKeyPair.generate(),
            }
        )

        bundle_b = OmemoBundle(
            EdKeyPair.generate(),
            XKeyPair.generate(),
            {
                "0": XKeyPair.generate(),
                "1": XKeyPair.generate(),
                "2": XKeyPair.generate(),
            }
        )

        omemo_a = Omemo(bundle_a)
        omemo_b = Omemo(bundle_b)

        message = "Initial OMEMO message (1234567890)."
        ik_b = bundle_b.get_indentity().get_public_key() 
        spk_b = bundle_b.get_prekey().get_public_key() 
        sign_b = bundle_b.get_indentity().sign_public_key(spk_b, encoding=None) 
        opk_id = "0"
        opk_b = bundle_b.get_onetime_prekey(opk_id).get_public_key()
        

        SK_A, EK_A, en_message = omemo_a.create_init_message(
            message=message,
            indentity_key=ik_b,
            signed_prekey=spk_b,
            prekey_signature=sign_b,
            onetime_prekey=opk_b,
        )

        ik_a = bundle_a.get_indentity().get_public_key() 
        ek_a = EK_A
        spk_id = "0"
        msg = en_message

        SK_B, de_message = omemo_b.accept_init_message(
            encrypted_message=msg,
            indentity_key=ik_a,
            ephemeral_key=ek_a,
            spk_id=spk_id,
            opk_id=opk_id
        )

        self.assertEqual(SK_A, SK_B)
        self.assertEqual(message, de_message.decode("utf-8"))
