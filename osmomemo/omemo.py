import os
import json
import base64

from typing import Tuple, List

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  

from .bundle import OmemoBundle
from .storage import OmemoStorage
from .key import XKeyPair, EdKeyPair 
from .crypto import OmemoCryptography as OmemoCrypto

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

class Omemo:
    def __init__(self, bundle: OmemoBundle, storage: OmemoStorage):
        self._bundle = bundle
        self._storage = storage

    def get_device_list(self, jid) -> List[int] | None:
        try:
            return self._storage.get_device_list(jid)
        except:
            return None

    def create_init_message(
                self,
                jid: str,
                device: int,
                message_bytes: bytes,
                indentity_key: Ed25519PublicKey,
                signed_prekey: X25519PublicKey,
                prekey_signature: bytes,
                onetime_prekey: X25519PublicKey,
            ) -> Tuple[bytes, bytes, bytes]:
        # Key pairs
        indentity_pair = self._bundle.get_indentity()

        # Create nonce for receive and send
        # Session nonces will be dinamic in future 
        session_nonces = os.urandom(24)

        # Combine nonce with message to encrypt
        message = session_nonces + message_bytes

        SK, ek_pub, encrypted_message = OmemoCrypto.create_init_message(
                message_bytes=message,
                indentity_pair=indentity_pair,
                indentity_key=indentity_key,
                signed_prekey=signed_prekey,
                prekey_signature=prekey_signature,
                onetime_prekey=onetime_prekey,
        )

        SK_RECV, SK_SEND = OmemoCrypto.split_secret_key(SK)

        self._storage.add_device(jid, device)
        self._storage.add_session(
                jid=jid, 
                device=device, 
                receive_secret_key=b64(SK_RECV), 
                send_secret_key=b64(SK_SEND),
                receive_nonce=b64(session_nonces[:12]),
                send_nonce=b64(session_nonces[12:]), 
        )

        return ek_pub, encrypted_message 

    def accept_init_message(
                self,
                jid: str,
                device: int,
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

        # Seperate nonces and messsage
        session_nonces = message_bytes[:24]
        message = message_bytes[24:]

        SK_SEND, SK_RECV = OmemoCrypto.split_secret_key(SK)

        self._storage.add_device(jid, device)
        self._storage.add_session(
                jid=jid, 
                device=device, 
                receive_secret_key=b64(SK_RECV), 
                send_secret_key=b64(SK_SEND),
                receive_nonce=b64(session_nonces[12:]),
                send_nonce=b64(session_nonces[:12]), 
        )

        return message

    def send_message(self, jid: str, device: int, message_bytes: bytes) -> Tuple[bytes, bytes, bytes]:
        session = self._storage.get_session(jid, device)
        
        send_nonce = os.urandom(12)
        message = send_nonce + message_bytes

        next_ck, wrapped, payload = OmemoCrypto.send_message(
                ub64(session.send_secret_key), 
                ub64(session.send_nonce), 
                message
        )

        self._storage.update_send_secret(jid, device, b64(next_ck))
        self._storage.set_send_nonce(jid, device, send_nonce)
        return wrapped, payload

    def receive_message(self, jid: str, device: int, wrapped_message_key: bytes, payload: bytes) -> Tuple[bytes, bytes, bytes]:
        session = self._storage.get_session(jid, device)

        next_ck, message_bytes = OmemoCrypto.receive_message(
                ub64(session.receive_secret_key), 
                ub64(session.receive_nonce), 
                wrapped_message_key, 
                payload
        )

        receive_nonce = message_bytes[:12]
        message = message_bytes[12:]

        self._storage.update_receive_secret(jid, device, b64(next_ck))
        self._storage.set_receive_nonce(jid, device, b64(receive_nonce))
        return message

    def close_storage(self):
        pass
