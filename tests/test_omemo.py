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
        sign_b = bundle_b.get_prekey_signature(encoding=None) 
        opk_id = "0"
        opk_b = bundle_b.get_onetime_prekey(opk_id).get_public_key()
        

        SK_A, EK_A, en_message = omemo_a.create_init_message(
            message_bytes=message.encode(),
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
        self.assertEqual(message, de_message.decode())

    def test_send(self):
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
        sign_b = bundle_b.get_prekey_signature(encoding=None) 
        opk_id = "0"
        opk_b = bundle_b.get_onetime_prekey(opk_id).get_public_key()
        

        SK_A, EK_A, en_message = omemo_a.create_init_message(
            message_bytes=message.encode(),
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
        self.assertEqual(message, de_message.decode())


        ### Sending
        ## Alice
        message_a = "Hello Bob! How are you?"
        count_a_s = 0
        count_a_r = 0

        # Recv, Send
        SK_A_R, SK_A_S = omemo_a.split_secret_key(SK_A)

        SK_A_S, wrapped_a, payload_a = omemo_a.send_message(SK_A_S, count_a_s, message_a.encode())
        count_a_s += 1

        ## Bob
        count_b_s = 0
        count_b_r = 0

        # Send, Recv (The order is crucial) "SK_A_S" must be equal "SK_B_R"
        SK_B_S, SK_B_R = omemo_b.split_secret_key(SK_B)

        SK_B_R, message_b = omemo_b.receive_message(SK_B_R, count_b_r, wrapped_a, payload_a)
        count_b_r += 1

        # TEST
        self.assertEqual(message_a, message_b.decode())



        message_b = "Hi, Alice! I am good =)"

        SK_B_S, wrapped_b, payload_b = omemo_b.send_message(SK_B_S, count_b_s, message_b.encode())
        count_a_s += 1

        SK_A_R, message_a = omemo_a.receive_message(SK_A_R, count_a_r, wrapped_b, payload_b)
        count_b_r += 1

        # Test
        self.assertEqual(message_b, message_a.decode())
