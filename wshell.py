import websocket
import time
import rel
import msg_pb2
import secrets
from collections import namedtuple
from dissononce.dh.x25519.x25519 import X25519DH, PublicKey, PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from types import SimpleNamespace
from base64 import b64encode as be
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

unknown_P = [0x57, 0x41, 0x6, 0x2]


class Client(object):
	"""
	class to represent a client instance
	"""
	websocket_url = "wss://web.whatsapp.com/ws/chat"
	header = ["User-Agent: Chrome/100.0.4896.127"]

	def __init__(self, ws:websocket=None, prekey_id:int=None, noise_info_iv:list=None, recovery_token:bytes=None,\
							static_private_bytes:bytes=None, ephemeral_private_bytes:bytes=None, ident_private_bytes:bytes=None,\
							reg_id:bytes=None, debug:bool=False):
		self.counter        = 0
		self.prekey_id      = prekey_id or 0
		self.noise_info_iv  = noise_info_iv or [be(secrets.token_bytes(16)) for _ in range(3)]
		self.recovery_token = recovery_token or secrets.token_bytes(24)
		if static_private_bytes is not None:
			static_private_bytes = PrivateKey(static_private_bytes)
		self.cstatic_key    = X25519DH().generate_keypair(privatekey=static_private_bytes)
		if ephemeral_private_bytes is not None:
			ephemeral_private_bytes = PrivateKey(ephemeral_private_bytes)
		self.cephemeral_key = X25519DH().generate_keypair(privatekey=ephemeral_private_bytes) 
		self.cident_key     = SimpleNamespace(public=None, private=None)
		self.prekey         = SimpleNamespace(public=None, private=None)
		self.salt           = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
		self.meta = {"signal_last_spk_id": None}
		self.signed_prekey_store = {}
		self._id_to_signed_prekey = {}

		self.shared_key = None
		
		if ident_private_bytes is not None:
			self.cident_key.private = Ed25519PrivateKey.from_private_bytes(ident_private_bytes)
		else:
			self.cident_key.private = Ed25519PrivateKey.generate()
		
		self.cident_key.public  = self.cident_key.private.public_key()

		self.reg_id = reg_id or secrets.token_bytes(2)
		
		if debug:
			websocket.enableTrace(True)

		self.ws = ws

	def _connect(self):
		"""
		open a websocket connection
		"""
		self.ws = websocket.WebSocket()
		self.ws.connect(self.websocket_url, header=self.header)

	def _gen_signed_prekey(self, private_bytes:bytes=None):
		"""
		generate PreShareKeys and Sign the public key with the Identity Key
		"""
		if private_bytes is not None:
			self.prekey.private = Ed25519PrivateKey.from_private_bytes(private_bytes)
		else:
			self.prekey.private = Ed25519PrivateKey.generate()
		
		self.prekey.public = self.prekey.private.public_key()
		_pub_bytes = self.prekey.public.public_bytes(encoding=serialization.Encoding.Raw, 
															format=serialization.PublicFormat.Raw
															)
		self.prekey_sig = self.cident_key.private.sign(_pub_bytes)

		# put the keypair into the prekey store
		self.signed_prekey_store[self.prekey_id] = (self.prekey, self.prekey_sig)

	def _get_registration_info(self):
		"""
		get registration info
		"""
		return (self.reg_id, self.cident_key.public, self.cident_key.private)

	def _get_signed_prekey(self):
		"""
		get prekey w/ signature
		"""
		return (self.prekey.public, self.prekey.private, self.prekey_sig)

	def _to_signal_curve_keypair(self):
		return (b'5' + self.cident_key.public, self.cident_key.private)

	def _gen_signed_key_pair(self):
		pass

	def _rotate_signed_prekey(self):
		"""
		set prekey id and set in meta dict
		"""
		self.prekey_id += 1
		self.meta['signal_last_spk_id'] = self.prekey_id

	def _shared_secret(self, keypair=None, pubkey=None):
		"""
		sharedSecret function on Line#35247
		"""
		if keypair is None:
			keypair = self.cephemeral_key
		return X25519DH().dh(keypair, pubkey)

	def _mix_into_key(self, salt:bytes=None, key:bytes=None):
		"""
		use hkdf with the salt and the shared_key to compute decryption key
		and return two slices of [:32] and [32:]
		"""
		if salt is None:
			salt = self.salt
		hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=None)
		key = hkdf.derive(key)
		return (key[:32], key[32:])

	def _process_server_hello(self, shello):
		"""
		process server hello on line  61035 a.k.a `function w(e, t, n)`
		"""
		print(f":. processing server hello> {shello}")
		print(f":. ==== [({len(shello.ephemeral), type(shello.ephemeral)}), ({len(shello.static), type(shello.static)}), ({len(shello.payload), type(shello.payload)})] ====")
		shared_key = self._shared_secret(pubkey=PublicKey(shello.ephemeral))
		print(f":. shared_secret is {shared_key}")
		self.salt, _key = self._mix_into_key(key=shared_key)
		print(f":. salt ~>{self.salt}\n:. _key[{len(_key)}] ~> {_key}")
		aesgcm = AESGCM(_key)

	def start(self):
		self._connect()
		self._rotate_signed_prekey()
		self._gen_signed_prekey()

		print("\n****** CLIENT STATE BEG ******")
		print(f"PREKEY_ID      : {self.prekey_id}\
					\nNOISE_INFO_IV  : {self.noise_info_iv}\
					\nREGISTRATION_ID: {self.reg_id}\
					\nSTATIC_KEY     : {self.cstatic_key.public}; {self.cstatic_key.private}\
					\nEPHEMERAL_KEY  : {self.cephemeral_key.public}; {self.cephemeral_key.private}\
					\nIDENTITY_KEY   : {self.cident_key.public}; {self.cident_key.private}\
					\nPREKEY         : {self.prekey.public}; {self.prekey.private}\
					\nPREKEY_SIG     : {self.prekey_sig}\
					\n****** CLIENT STATE END ******\n")
		chello = msg_pb2.ClientHello()
		chello.ephemeral = self.cephemeral_key.public.data
		chello_msg = b"\x57\x41\x06\x02\x00\x00\x24\x12\x22" + chello.SerializeToString()
		self.ws.send_binary(chello_msg)

		# receive server hello
		shello = msg_pb2.ServerHello()
		recv_data = self.ws.recv_frame()
		shello.ParseFromString(recv_data.data[6:])

		print(f'\n:. static:{len(shello.static)} ephemeral:{len(shello.ephemeral)} payload:{len(shello.payload)}')

		self._process_server_hello(shello)

if __name__ == "__main__":
	client = Client(debug=True)
	client.start()
