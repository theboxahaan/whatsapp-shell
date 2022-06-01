import websocket
import msg_pb2
import secrets
from types import SimpleNamespace
from base64 import b64encode as be
from base64 import b64decode as bd
from dissononce.dh.x25519.x25519 import X25519DH, PublicKey, PrivateKey
from dissononce.dh.keypair import KeyPair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Union


def get_Ed25519Key_bytes(key:Union[Ed25519PublicKey, Ed25519PrivateKey]=None) -> bytes:
	#TODO migrate some stuff to `utils.py` 
	"""
	extract raw bytes from Ed25519Public/PrivateKey object
	@arg key: key from which raw bytes are to be extracted
	@return raw bytes of `key`
	"""
	if isinstance(key, Ed25519PublicKey):
		_tmp = key.public_bytes(
						encoding=serialization.Encoding.Raw,
						format=serialization.PublicFormat.Raw
					)
	elif isinstance(key, Ed25519PrivateKey):
		_tmp = key.private_bytes(
						encoding=serialization.Encoding.Raw,
						format=serialization.PrivateFormat.Raw,
						encryption_algorithm=serialization.NoEncryption()
					)
	else:
		print(f":. incorrect type key > {type(key)}")
		_tmp = None
	
	return _tmp 


class Client(object):
	"""
	class to represent a client instance
	WARNING - side effects abound. This client is purposefully written to reflect the JS
	client and hence it has a lot of side effects. However, the side effects are limited
	to the Client objects own parameters
	"""
	websocket_url = "wss://web.whatsapp.com/ws/chat"
	header = ["User-Agent: Chrome/100.0.4896.127"]
	INIT_SALT = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
	WA_HEADER = b"\x57\x41\x06\02" 


	def __init__(self, ws:websocket=None, prekey_id:int=None, noise_info_iv:list=None,\
							recovery_token:bytes=None, static_private_bytes:bytes=None,\
							ephemeral_private_bytes:bytes=None, ident_private_bytes:bytes=None,\
							reg_id:bytes=None, debug:bool=False):
		"""
		counter   :@updatable
		cryptokey :@updateable
		shared_key:@updateable
		salt      :@updateable
		hash      :@updateable
		"""
		self.counter        = 0
		self.cryptokey      = None
		self.shared_key     = None
		self.salt           = self.INIT_SALT
		self.hash           = self.INIT_SALT
		self.prekey_id      = prekey_id or 0
		self.noise_info_iv  = noise_info_iv or [be(secrets.token_bytes(16)) for _ in range(3)]
		# recover_token set by refreshNoiseCredentials()
		self.recovery_token = recovery_token or secrets.token_bytes(24)
		self.reg_id         = reg_id or secrets.token_bytes(2)
		self.ws             = ws

		#------------------[CLIENT KEYS]-----------------#
		self.cident_key     = SimpleNamespace(public=None, private=None)
		self.prekey         = SimpleNamespace(public=None, private=None)
		
		if static_private_bytes is not None:
			# set by refreshNoiseCredentials() Line #61186
			static_private_bytes = PrivateKey(static_private_bytes)
		self.cstatic_key    = X25519DH().generate_keypair(privatekey=static_private_bytes)
		
		if ephemeral_private_bytes is not None:
			ephemeral_private_bytes = PrivateKey(ephemeral_private_bytes)
		self.cephemeral_key = X25519DH().generate_keypair(privatekey=ephemeral_private_bytes) 
		
		if ident_private_bytes is not None:
			self.cident_key.private = Ed25519PrivateKey.from_private_bytes(ident_private_bytes)
		else:
			self.cident_key.private = Ed25519PrivateKey.generate()
		
		self.cident_key.public  = self.cident_key.private.public_key()

		#------------------[CLIENT DICTS]-----------------#
		self.meta                 = {"signal_last_spk_id": None}
		self.signed_prekey_store  = {}
		self._id_to_signed_prekey = {}

		if debug:
			websocket.enableTrace(True)


	def _connect(self):
		"""
		opens a websocket connection with the server
		"""
		self.ws = websocket.WebSocket()
		self.ws.connect(self.websocket_url, header=self.header)

	def _gen_signed_prekey(self, private_bytes:bytes=None):
		"""
		generates PreShareKeys and signs the public key with the Identity Key
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


	def _send_frame(self, intro_bytes:bytes=None, payload:bytes=None) -> int:
		"""
		append intro bytes, sizeof `payload` (cast to 3 bytes) to the actual payload and send
		via websocket
		@arg intro_bytes: bytes to be appended
		@arg payload    : payload to be sent
		@return length  : total length of sent bytes
		"""
		if intro_bytes is None:
			intro_bytes = b"" 
		final_pyld = intro_bytes + len(payload).to_bytes(3, "big") + payload
		self.ws.send_binary(final_pyld)
		return len(final_pyld)


	def _get_registration_info(self) -> tuple:
		"""
		get registration info
		"""
		return (self.reg_id, self.cident_key.public, self.cident_key.private)


	def _get_signed_prekey(self) -> tuple:
		"""
		get prekey w/ signature
		"""
		return (self.prekey_id, self.prekey.public, self.prekey.private, self.prekey_sig)


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


	def _shared_secret(self, keypair:KeyPair=None, pubkey:PublicKey=None) -> bytes:
		"""
		sharedSecret function on Line#35247
		update the self.shared_secret key by mixing the ephemeral keypair with the pubkey
		"""
		if keypair is None:
			keypair = self.cephemeral_key
		self.shared_key = X25519DH().dh(keypair, pubkey)
		return self.shared_key


	def _mix_into_key(self, salt:bytes=None, key_material:bytes=None):
		"""
		update self.salt, self.cryptokey using an hkdf
		"""
		self.counter = 0
		if salt is None:
			salt = self.salt
		if key_material is None:
			key_material = self.shared_key

		hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=None)
		key = hkdf.derive(key_material)
		self.salt = key[:32]
		self.cryptokey = AESGCM(key[32:]) 


	def _authenticate(self, e:bytes=None):
		"""
		authentication function used for something :/
		update self.hash
		"""
		_i = self.hash + e
		digest = hashes.Hash(hashes.SHA256())
		digest.update(_i)
		self.hash = digest.finalize()


	def _gen_iv(self, counter:int=None) -> bytes:
		"""
		convert a counter int into a 96 bit vector but strangely only the last 4 bytes
		are ever used
		#TODO check what happens when counter > 4 bytes 
		"""
		return b"\x00\x00\x00\x00\x00\x00\x00\x00" + counter.to_bytes(4, "big")


	def _encrypt(self, pt:bytes=None) -> bytes:
		"""
		encrypt plaintext `pt` using cryptokey
		"""
		try:
			_enc = self.cryptokey.encrypt(self._gen_iv(self.counter), pt, self.hash)
			self._authenticate(_enc)
			self.counter += 1
			return _enc
		except Exception as e:
			print(f":. encryption failed {e}")
			raise e



	def _decrypt(self, ct:bytes=None) -> bytes:
		"""
		decrypt ciphertext `ct`  using cryptokey
		@arg   : bytes - ct
		@return: bytes - decrypted bytes
		"""
		try:
			_dec = self.cryptokey.decrypt(self._gen_iv(self.counter), ct, self.hash)
			self._authenticate(ct)
			self.counter += 1
			return _dec
		except Exception as e:
			print(f":. decryption failed {e}")
			raise e


	def _get_client_payload_for_registration(self, reg_info:tuple=None,\
																					key_info:tuple=None, t:dict=None) -> bytes:
		"""
		function defined at Line #60338
		reg_info: @arg - returned by get_registration_info()
		key_info: @arg - returned by get_signed_prekey()
		t       : @arg - not exactly sure {passive: False, pull:False}
		
		payload : @return proto
		"""
		# this is the b64encoded string returned by memoizeWithArgs("2.2218.8")
		# on Line #60393
		# UPDATE
		# - memoizeWithArgs("2.2218.8") basically maps the version no to its MD5 hash
		# - _r = MD5("2.2218.8")
		# - a.k.a as the build hash

		if reg_info is None:
			reg_info = self._get_registration_info()
		if key_info is None:
			key_info = self._get_signed_prekey()
		if t is None:
			t = {'passive':False, 'pull':False}

		_digest = hashes.Hash(hashes.MD5())
		_digest.update(b"2.2218.8")
		_r = _digest.finalize()


		def _companion_prop_spec():
			"""
				return a protobuf with hardcoded companion specs
			"""
			spec = msg_pb2.CompanionPropsSpec()
			spec.os = "Mac OS"
			spec.version.primary = 10
			spec.version.secondary = 15
			spec.version.tertiary = 7
			spec.requireFullSync = False
			spec.platformType = 1
			return spec.SerializeToString()

		_a = _companion_prop_spec()

		# build final protobuf
		pyld = msg_pb2.ClientPayloadSpec()
		pyld.pull = t['pull'] 
		pyld.passive = t['passive']
		pyld.connectReason = 1
		pyld.connectType = 1
		pyld.webInfo.webSubPlatform = 0
		pyld.userAgent.platform = 14
		pyld.userAgent.osVersion = "0.1"
		pyld.userAgent.releaseChannel = 0
		pyld.userAgent.osBuildNumber = "0.1"
		pyld.userAgent.mnc = "000"
		pyld.userAgent.mcc = "000"
		pyld.userAgent.manufacturer = ""
		pyld.userAgent.localeLanguageIso6391 = "en"
		pyld.userAgent.localeCountryIso31661Alpha2 = "GB"
		pyld.userAgent.device = "Desktop"
		pyld.userAgent.appVersion.primary = 2
		pyld.userAgent.appVersion.secondary = 2218
		pyld.userAgent.appVersion.tertiary = 8
		pyld.devicePairingData.buildHash = _r
		pyld.devicePairingData.companionProps = _a
		pyld.devicePairingData.eIdent = get_Ed25519Key_bytes(reg_info[1])
		pyld.devicePairingData.eKeytype = b'\x05'
		pyld.devicePairingData.eRegid = b"\x00\x00" + reg_info[0]
		pyld.devicePairingData.eSkeyId = key_info[0].to_bytes(3, "big")
		pyld.devicePairingData.eSkeySig = key_info[3]
		pyld.devicePairingData.eSkeyVal = get_Ed25519Key_bytes(key_info[1])

		return pyld.SerializeToString()

	def _process_server_hello(self, shello:msg_pb2.ServerHello=None):
		"""
		process server hello on line  61035 a.k.a `function w(e, t, n)`
		"""
		self._shared_secret(pubkey=PublicKey(shello.ephemeral))
		self._authenticate(shello.ephemeral)
		self._mix_into_key()
		_dec_static_key = self._decrypt(shello.static)
		self._shared_secret(pubkey=PublicKey(_dec_static_key))
		self._mix_into_key()
		_dec_payload = self._decrypt(shello.payload)
		
		# verifyChainCertificateWA6 Line #61025 skipped

		# returned tuple by generator M() on Line #61095 is 
		# (_get_registration_info, _get_signed_prekey, s_eph)
		
		client_payload = self._get_client_payload_for_registration()

		# Line #61105 waNoiseInfo.get()....staticKeyPair
		# returns clients static keyPair
		_enc_static_key = self._encrypt(self.cstatic_key.public.data)
		self._shared_secret(keypair=self.cstatic_key, pubkey=PublicKey(shello.ephemeral)) 
		self._mix_into_key()

		# now encrypt client_payload
		_enc_client_payload = self._encrypt(client_payload)

		fin_msg = msg_pb2.HandshakeMessage()
		fin_msg.clientFinish.static = _enc_static_key
		fin_msg.clientFinish.payload = _enc_client_payload
		_l = self._send_frame(payload=fin_msg.SerializeToString())
		print(f':. sent client finish message of size > {_l}')

		srv_resp = self.ws.recv_frame()
		print(f':. received server data > {len(srv_resp.data)}')


	def client_dump(self) -> str:
		"""
		repr of client object
		"""
		return f"\n****** CLIENT STATE BEG ******\
					\nprekey_id      : {self.prekey_id}\
					\ncounter        : {self.counter}\
					\ncryptokey      : {self.cryptokey}\
					\nregistration_id: {self.reg_id}\
					\nshared_key     : {self.shared_key}\
					\nsalt           : {self.salt}\
					\nhash           : {self.hash[:6]}...\
					\nstatic_key     : {self.cstatic_key.public.data[:4]}...; \
{self.cstatic_key.private.data[:4]}...\
					\nephemeral_key  : {self.cephemeral_key.public.data[:4]}...;\
{self.cephemeral_key.private.data[:4]}...\
					\nprekey_sig     : {self.prekey_sig[:4]}...\
					\n****** CLIENT STATE END ******\n"

	def start(self):
		
		self._authenticate(self.WA_HEADER)

		self._connect()
		self._rotate_signed_prekey()
		self._gen_signed_prekey()
		
		print(self.client_dump())

		self._authenticate(self.cephemeral_key.public.data)
		chello = msg_pb2.HandshakeMessage()
		chello.clientHello.ephemeral = self.cephemeral_key.public.data
		_l = self._send_frame(intro_bytes=self.WA_HEADER, payload=chello.SerializeToString())
		print(f':. sent client hello msg of size > {_l}')

		# receive server hello
		shello = msg_pb2.HandshakeMessage()
		recv_data = self.ws.recv_frame()
		print(f':. recvd server hello msg > {len(recv_data.data)}')

		# parse from the 4th byte as first 3 bytes encode the length
		shello.ParseFromString(recv_data.data[3:])
		self._process_server_hello(shello.serverHello)
	
if __name__ == "__main__":
	client = Client(debug=False)
	client.start()
