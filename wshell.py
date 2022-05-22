import websocket
import time
import rel
import msg_pb2
import secrets
from collections import namedtuple
from dissononce.dh.x25519.x25519 import X25519DH

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from types import SimpleNamespace
from base64 import b64encode as be

from Crypto.Cipher import AES

class Client(object):
	"""
	class to represent a client instance
	"""
	websocket_url = "wss://web.whatsapp.com/ws/chat"
	header = ["User-Agent: Chrome/100.0.4896.127"]

	def __init__(self, ws:websocket=None, debug:bool=False):
		self.counter        = 0
		self.prekey_id      = 0
		self.noise_info_iv  = [be(secrets.token_bytes(16)) for _ in range(3)]
		self.recovery_token = secrets.token_bytes(24)
		self.cstatic_key    = X25519DH().generate_keypair()
		self.cephemeral_key = X25519DH().generate_keypair() 
		self.cident_key     = SimpleNamespace(public=None, private=None)
		self.prekey         = SimpleNamespace(public=None, private=None)
		
		self.meta = {"signal_last_spk_id": None}
		self.signed_prekey_store = {}
		self._id_to_signed_prekey = {}

		self.shared_key = None

		self.cident_key.private = Ed25519PrivateKey.generate()
		self.cident_key.public  = self.cident_key.private.public_key()

		self.reg_id = secrets.token_bytes(2)
		
		if debug:
			websocket.enableTrace(True)

		self.ws = ws

	def _connect(self):
		"""
		open a websocket connection
		"""
		self.ws = websocket.WebSocket()
		self.ws.connect(self.websocket_url, header=self.header)

	def _gen_signed_prekey(self):
		"""
		generate PreShareKeys and Sign the public key with the Identity Key
		"""
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

	def start(self):
		self._connect()
		self._rotate_signed_prekey()
		self._gen_signed_prekey()

		chello = msg_pb2.ClientHello()
		chello.ephemeral = self.cephemeral_key.public.data
		chello_msg = b"\x57\x41\x06\x02\x00\x00\x24\x12\x22" + chello.SerializeToString()
		self.ws.send_binary(chello_msg)

		# receive server hello
		shello = msg_pb2.ServerHello()
		recv_data = self.ws.recv_frame()
		shello.ParseFromString(recv_data.data[6:])

		print(f'\n:. static:{len(shello.static)} ephemeral:{len(shello.ephemeral)} payload:{len(shello.payload)}')

if __name__ == "__main__":
	client = Client(debug=True)
	client.start()
