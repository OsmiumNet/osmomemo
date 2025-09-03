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
from .crypto import OmemoCryptography as OmemoCrypto

class Omemo:
    def __init__(self, bundle: OmemoBundle):
        self._bundle = bundle

    def create_init_message(
                self,
                message_bytes: bytes,
                indentity_key: Ed25519PublicKey,
                signed_prekey: X25519PublicKey,
                prekey_signature: bytes,
                onetime_prekey: X25519PublicKey,
            ) -> Tuple[bytes, bytes, bytes]:
        # Key pairs
        indentity_pair = self._bundle.get_indentity()

        SK, ek_pub, encrypted_message = OmemoCrypto.create_init_message(
                message_bytes=message_bytes,
                indentity_pair=indentity_pair,
                indentity_key=indentity_key,
                signed_prekey=signed_prekey,
                prekey_signature=prekey_signature,
                onetime_prekey=onetime_prekey,
        )

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
        
        SK, message_bytes = OmemoCrypto.accept_init_message(
                encrypted_message=encrypted_message,
                indentity_pair=indentity_pair,
                prekey_pair=prekey_pair,
                onetime_prekey_pair=onetime_prekey_pair,
                indentity_key=indentity_key,
                ephemeral_key=ephemeral_key,
        )

        return SK, message_bytes

    def split_secret_key(self, secret_key) -> Tuple[bytes, bytes]:
        ck1, ck2 = OmemoCrypto.split_secret_key(secret_key)  
        return ck1, ck2

    def send_message(self, chain_key, count, message_bytes) -> Tuple[bytes, bytes, bytes]:
        next_ck, wrapped, payload = OmemoCrypto.send_message(chain_key, count, message_bytes)
        return next_ck, wrapped, payload

    def receive_message(self, chain_key, count, wrapped_message_key, payload) -> Tuple[bytes, bytes, bytes]:
        next_ck, message = OmemoCrypto.receive_message(chain_key, count, wrapped_message_key, payload)
        return next_ck, message
