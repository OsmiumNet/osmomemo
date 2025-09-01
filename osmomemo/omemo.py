import os
import json

from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  

from .key import XKeyPair, EdKeyPair 
from .bundle import OmemoBundle

class Omemo:
    def __init__(self, bundle: OmemoBundle):
        self._bundle = bundle

    def create_init_message(
                self,
                message: str,
                indentity_key: Ed25519PublicKey,
                signed_prekey: X25519PublicKey,
                prekey_signature: bytes,
                onetime_prekey: X25519PublicKey,
            ) -> Tuple[bytes, bytes, bytes]:
        
        # Verify signed PreKey signature
        EdKeyPair.verify_public_key(
                verifier=indentity_key,
                public_key=signed_prekey,
                signature=prekey_signature
        )

        # Key pairs
        indentity_pair = self._bundle.get_indentity()
        # We are the initiator, so we must generate a ephemeral key
        ephemeral_pair = XKeyPair.generate()

        # Private keys
        ik = indentity_pair.get_x_private_key()
        ek = ephemeral_pair.get_private_key()  

        # Make Elliptic Curve Diffie-Hellman parts
        DH1 = ik.exchange(signed_prekey)
        DH2 = ek.exchange(EdKeyPair.public_ed_to_x_key(indentity_key))
        DH3 = ek.exchange(signed_prekey)
        DH4 = ek.exchange(onetime_prekey)

        # Calculate Secret Key
        SK = self._hkdf_derive([DH1, DH2, DH3, DH4]) 

        # Delete ephemeral
        ek_pub = ephemeral_pair.get_public_key()
        del ephemeral_pair  
        del ek

        # Derive an AEAD key and encrypt the initial payload
        aead_key = self._hkdf_derive([SK])
        aesgcm = AESGCM(aead_key)
        nonce = os.urandom(12)
        initial_plain = message.encode("utf-8")
        ct = aesgcm.encrypt(nonce, initial_plain, None)
        encrypted_message = nonce + ct

        return SK, ek_pub, encrypted_message 

    def accept_init_message(
                self,
                encrypted_message: bytes,
                indentity_key: Ed25519PublicKey,
                ephemeral_key: X25519PublicKey,
                spk_id: str,
                opk_id: str,
            ) -> Tuple[bytes, bytes]:
        
        # Key pairs
        indentity_pair = self._bundle.get_indentity()
        prekey_pair = self._bundle.get_prekey()
        onetime_prekey_pair = self._bundle.get_onetime_prekey(opk_id)

        # Private keys
        ik = indentity_pair.get_x_private_key()
        spk = prekey_pair.get_private_key()
        opk = onetime_prekey_pair.get_private_key()

        # Make Elliptic Curve Diffie-Hellman parts
        DH1 = spk.exchange(EdKeyPair.public_ed_to_x_key(indentity_key))
        DH2 = ik.exchange(ephemeral_key)
        DH3 = spk.exchange(ephemeral_key)
        DH4 = opk.exchange(ephemeral_key)

        # Calculate Secret Key
        SK = self._hkdf_derive([DH1, DH2, DH3, DH4]) 

        # Derive an AEAD key and encrypt the initial payload
        aead_key = self._hkdf_derive([SK])
        aesgcm = AESGCM(aead_key)
        nonce = encrypted_message[:12]; 
        ct = encrypted_message[12:]
        message = aesgcm.decrypt(nonce, ct, None)

        return SK, message 


    def _hkdf_derive(self, parts, info=b"OMEMO X3DH", length=32, salt=None):
        hk = HKDF(algorithm=hashes.SHA256(), info=info, length=length, salt=salt)
        return hk.derive(b"".join(parts))

