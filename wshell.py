import websocket
import secrets
import gzip
import qrcode
import io
import traceback
from base64 import b64encode as be
from base64 import b64decode as bd
from dissononce.dh.x25519.x25519 import X25519DH, PublicKey, PrivateKey
from dissononce.dh.keypair import KeyPair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Union

import msg_pb2
import proto_utils
import wap
import axolotl_curve25519 as curve
import utils


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
		self.adv_secret_key = be(secrets.token_bytes(32))

		#------------------[CLIENT KEYS]-----------------#
		if static_private_bytes is not None:
			# set by refreshNoiseCredentials() Line #61186
			static_private_bytes = PrivateKey(static_private_bytes)
		self.cstatic_key    = X25519DH().generate_keypair(privatekey=static_private_bytes)
		
		if ephemeral_private_bytes is not None:
			ephemeral_private_bytes = PrivateKey(ephemeral_private_bytes)
		self.cephemeral_key = X25519DH().generate_keypair(privatekey=ephemeral_private_bytes) 
		
		if ident_private_bytes is not None:
			ident_private_bytes = PrivateKey(ident_private_bytes)
		self.cident_key = X25519DH().generate_keypair(privatekey=ident_private_bytes)
		

		#------------------[CLIENT DICTS]-----------------#
		# stand ins for cookies and databases
		self.meta                 = {"signal_last_spk_id": None}
		self.signed_prekey_store  = {}
		self._id_to_signed_prekey = {}


		#------------------[NOISE CIPHERS]----------------#
		# the noise socket's AESGCM objects used for encryption and decryption of 
		# messages respectively
		self.noise_enc = None
		self.noise_dec = None
		self.noise_enc_counter = 0
		self.noise_dec_counter = 0

		if debug:
			websocket.enableTrace(True)


	def _connect(self):
		"""
		opens a websocket connection with the server
		"""
		self.ws = websocket.WebSocket()
		cookie_str = 'wa_lang_pref=en; wa_beta_version=production%2F1654038811%2F2.2220.8'
		self.ws.connect(self.websocket_url, header=self.header, origin="https://web.whatsapp.com",\
		host="web.whatsapp.com", cookie=cookie_str)


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
		print(f'-> size: {len(final_pyld)}')
		self.ws.send_binary(final_pyld)
		return len(final_pyld)

	#TODO remove `_` from name as it is being used outside the class
	def _recv_frame(self) -> bytes:
		"""
		generator
		receive `binary_frame` from server and parse it to return `data` bytes
		@return payload bytes
		"""
		pyld = self.ws.recv_frame()
		print(f'<- size: {len(pyld.data)}')
		if len(pyld.data) <= 4:
			return pyld.data
		recv_stream = wap.create_stream(pyld.data)
		while True:
			pyld_len = int.from_bytes(recv_stream.read(3), 'big')
			if pyld_len == 0:
				break
			else:
				yield recv_stream.read(pyld_len)

		
	def _gen_signed_prekey(self, private_bytes:bytes=None):
		"""
		generates PreShareKeys and signs the public key with the Identity Key
		UPDATE
		implements the ed25519 signing algo used by libsignal-protocol. It is different from
		the Ed25519 signing used by other libraries - needs to be explored.
		Ref-
		`generateSignedPreKey` @ Line #5467
		Notes-
		The signature is on the payload - b'\x05' + self.prekey.public bytes using the cident key
		"""
		#TODO implement axolotl.curve as a standalone .py script or atleast investigate those
		# bindings to create my own
		self.prekey = X25519DH().generate_keypair(privatekey = private_bytes)
		self.prekey_sig = curve.calculateSignature(secrets.token_bytes(64), self.cident_key.private.data,\
		b'\x05' + self.prekey.public.data)

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


	def _extract_with_salt_and_expand(self, salt:bytes=None, key_material:bytes=None):
		"""
		reconstruction of `extractWithSaltAndExpand` on Line #11384
		"""
		if salt is None:
			salt = self.salt
		hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=None)
		key = hkdf.derive(key_material)
		return key

	def _mix_into_key(self, salt:bytes=None, key_material:bytes=None):
		"""
		update self.salt, self.cryptokey using an hkdf
		reconstruction of `mixIntoKey` found on Line #11482
		"""
		self.counter = 0
		if salt is None:
			salt = self.salt
		if key_material is None:
			key_material = self.shared_key
		key = self._extract_with_salt_and_expand(salt, key_material)
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
		encrypt plaintext `pt` using cryptokey. reconstruction of `encrypt()` found on 
		Line #11438
		@arg pt: plaintext to be encrypted
		@return bytes: encrypted bytes
		"""
		try:
			_enc = self.cryptokey.encrypt(self._gen_iv(self.counter), pt, self.hash)
			self._authenticate(_enc)
			self.counter += 1
			return _enc
		except Exception as e:
			print(f":. encryption failed\n {traceback.print_exc()}")
			raise e



	def _decrypt(self, ct:bytes=None) -> bytes:
		"""
		decrypt ciphertext `ct`  using cryptokey. reconstruction of `decrypt()` found on
		Line #11454
		@arg   : bytes - ct
		@return: bytes - decrypted bytes
		"""
		try:
			_dec = self.cryptokey.decrypt(self._gen_iv(self.counter), ct, self.hash)
			self._authenticate(ct)
			self.counter += 1
			return _dec
		except Exception as e:
			print(f":. decryption failed\n {traceback.print_exc()}")
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
		# this is the b64encoded string returned by memoizeWithArgs("2.2220.8")
		# on Line #60393
		# UPDATE
		# - memoizeWithArgs("2.2220.8") basically maps the version no to its MD5 hash
		# - _r = MD5("2.2220.8")
		# - a.k.a as the build hash

		if reg_info is None:
			reg_info = self._get_registration_info()
		if key_info is None:
			key_info = self._get_signed_prekey()
		if t is None:
			t = {'passive':False, 'pull':False}

		_digest = hashes.Hash(hashes.MD5())
		_digest.update(b"2.2220.8")
		_r = _digest.finalize()

		# build client side protobufs
		spec = msg_pb2.CompanionPropsSpec()
		proto_utils.update_protobuf(spec, proto_utils.defaults.CompanionPropsSpec)
		_a = spec.SerializeToString()

		# build final protobuf
		pyld_spec = msg_pb2.ClientPayloadSpec()
		proto_utils.update_protobuf(pyld_spec, proto_utils.defaults.ClientPayloadSpec)
		proto_utils.update_protobuf(pyld_spec, t)
		
		proto_utils.update_protobuf(pyld_spec, {
			'devicePairingData': {
				'buildHash': _r,
				'companionProps': _a,
				'eIdent': reg_info[1].data,
				'eRegid': b'\x00\x00' + reg_info[0],
				'eSkeyId': key_info[0].to_bytes(3, 'big'),
				'eSkeySig': key_info[3],
				'eSkeyVal': key_info[1].data
			}
		})
		return pyld_spec.SerializeToString()

	def _process_server_hello(self, shello:msg_pb2.ServerHello=None):
		"""
		process server hello on line  61035 a.k.a `function w(e, t, n)`
		"""
		#TODO clean server ephemeral saving up
		self.server_ephemeral = shello.ephemeral

		self._shared_secret(pubkey=PublicKey(shello.ephemeral))
		self._authenticate(shello.ephemeral)
		self._mix_into_key()
		_dec_static_key = self._decrypt(shello.static)
		self._shared_secret(pubkey=PublicKey(_dec_static_key))
		self._mix_into_key()
		_dec_payload = self._decrypt(shello.payload)
		
		# verifyChainCertificateWA6 Line #61025 skipped

	def _send_client_finish(self):

		# returned tuple by generator M() on Line #61095 is 
		# (_get_registration_info, _get_signed_prekey, s_eph)
		
		client_payload = self._get_client_payload_for_registration()

		# Line #61105 waNoiseInfo.get()....staticKeyPair
		# returns clients static keyPair
		_enc_static_key = self._encrypt(self.cstatic_key.public.data)
		self._shared_secret(keypair=self.cstatic_key, pubkey=PublicKey(self.server_ephemeral)) 
		self._mix_into_key()

		# now encrypt client_payload
		_enc_client_payload = self._encrypt(client_payload)

		fin_msg = msg_pb2.HandshakeMessage()
		fin_msg.clientFinish.static = _enc_static_key
		fin_msg.clientFinish.payload = _enc_client_payload
		_l = self._send_frame(payload=fin_msg.SerializeToString())



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

	def initiate_noise_handshake(self):
		
		self._authenticate(self.WA_HEADER)

		self._connect()
		self._rotate_signed_prekey()
		self._gen_signed_prekey()
		
		print(self.client_dump())

		self._authenticate(self.cephemeral_key.public.data)
		chello = msg_pb2.HandshakeMessage()
		chello.clientHello.ephemeral = self.cephemeral_key.public.data
		_l = self._send_frame(intro_bytes=self.WA_HEADER, payload=chello.SerializeToString())

		# receive server hello
		recv_data = next(self._recv_frame())
		shello = msg_pb2.HandshakeMessage()

		shello.ParseFromString(recv_data)
		self._process_server_hello(shello.serverHello)

		self._send_client_finish()


	def finish(self):
		"""
		create two AESGCM objects for encryption/decryption respectively
		"""
		_k = self._extract_with_salt_and_expand(self.salt, b"")
		self.noise_enc, self.noise_dec = AESGCM(_k[:32]), AESGCM(_k[32:])
		
	
if __name__ == "__main__":
	
	client = Client(debug=False)
	client.initiate_noise_handshake()
	client.finish()
	srv_resp = next(client._recv_frame())
	
	# refer to `_handleCiphertext on Line #11528
	dec = client.noise_dec.decrypt(client._gen_iv(client.noise_dec_counter), srv_resp, b"")
	client.noise_dec_counter += 1
	assert len(dec) == 588

	dec_stream = wap.create_stream(dec)
	if int.from_bytes(dec_stream.read(1), 'big') & 2 != 0:
		print(f'might need to gzip inflate')
		raise NotImplementedError
	
	parsed_dec = wap.Y(dec_stream)
	#print(f"parsed id ~> {parsed_dec.attrs['id']}")
	print(parsed_dec.attrs)
	ref_v = [parsed_dec.content[0].content[i].content for i in range(6)]
	ref = ref_v[0]
	# `castStanza` on Line #47522
	# Convert `M` type wap object to a buffer using function `N(e, t)` on Line #10727

	# serialize WAPJID("iq", {"to": _jid: {server: "s.whatsapp.net", type: 0, user: None},
	#                         "type": "result", "id": parsed_id })
	# _.encodeStanza(...) @ Line #35561
	# N(e,t)
	_a = wap.WapJid.create(e=None, t='s.whatsapp.net')
	_x = wap.WAPNode(tag="iq", content=None, attrs={"to":_a, "type":'result', "id": parsed_dec.attrs['id']})
	t = io.BytesIO()
	wap.N(_x, t)
	t.seek(0)
	_buf = b'\x00' + t.read()

	enc = client.noise_enc.encrypt(client._gen_iv(client.noise_enc_counter), _buf, b"")
	client.noise_enc_counter += 1

	client._send_frame(payload=enc)

	qr_string = ref.decode() + "," + be(client.cstatic_key.public.data).decode() + ","\
	+ be(client.cident_key.public.data).decode() + ","\
	+ client.adv_secret_key.decode()

	print('qr string >', qr_string)

	#FIXME scaling issue when using print_tty
	qr = qrcode.QRCode(
			version=1,
			error_correction=qrcode.constants.ERROR_CORRECT_L,
			box_size=5,
			border=2
	)
	qr.add_data(qr_string)
	qr.make(fit=True)
	qr.print_ascii(tty=True, invert=True)

	while True:
		for resp in client._recv_frame():
			if len(resp) > 4:
				dec = client.noise_dec.decrypt(client._gen_iv(client.noise_dec_counter), resp, None)
				client.noise_dec_counter+=1
				# parse response
				t = wap.create_stream(dec)
				t.read(1)
				s = wap.Y(t)
				print(s.attrs, s.tag, s.content)
			else:
				print(resp)
