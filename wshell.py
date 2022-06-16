import secrets
import time
import qrcode
import io
import hmac
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
from frame import FrameSocket

class Client(object):
	"""
	class to represent a client instance
	WARNING - side effects abound. This client is purposefully written to reflect the JS
	client and hence it has a lot of side effects. However, the side effects are limited
	to the Client objects own parameters
	"""
	INIT_SALT = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
	WA_HEADER = b"\x57\x41\x06\02" 


	def __init__(self, prekey_id:int=None, noise_info_iv:list=None,\
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
		self.ws             = FrameSocket(debug=debug)
		self.adv_secret_key = be(secrets.token_bytes(32))
		self.debug          = debug

		#------------------[CLIENT KEYS]-----------------#
		# set by refreshNoiseCredentials() Line #61186
		if static_private_bytes is not None:
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

		self.username = None
		self.device   = None


	def reset_conn(self):
		"""reset `Client` so that it can be re-used for login after registration"""
		self.counter = 0
		self.cryptokey = None
		self.shared_key = None
		self.salt = self.INIT_SALT
		self.hash = self.INIT_SALT
		self.ws = FrameSocket(self.debug)

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
		""" get registration info """
		return (self.reg_id, self.cident_key.public, self.cident_key.private)


	def _get_signed_prekey(self) -> tuple:
		""" get prekey w/ signature """
		return (self.prekey_id, self.prekey.public, self.prekey.private, self.prekey_sig)


	def _rotate_signed_prekey(self):
		""" set prekey id and set in meta dict """
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


	def _encrypt(self, pt:bytes=None) -> bytes:
		"""
		encrypt plaintext `pt` using cryptokey. reconstruction of `encrypt()` found on 
		Line #11438
		@arg pt: plaintext to be encrypted
		@return bytes: encrypted bytes
		"""
		try:
			_enc = self.cryptokey.encrypt(utils.gen_iv(self.counter), pt, self.hash)
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
			_dec = self.cryptokey.decrypt(utils.gen_iv(self.counter), ct, self.hash)
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


	def _get_client_payload_for_login(self):
		"""
		`getClientPayloadForLogin` @ Line #61560
		"""
		pyld_spec = msg_pb2.ClientPayloadSpec()
		proto_utils.update_protobuf(pyld_spec, proto_utils.defaults.ClientPayloadSpec1)
		proto_utils.update_protobuf(pyld_spec, {
			'passive':True,
			'pull':False,
			'username': int(self.username),
			'device': self.device
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


	def _send_client_finish(self, login:bool=False):

		# returned tuple by generator M() on Line #61095 is 
		# (_get_registration_info, _get_signed_prekey, s_eph)
		if login:
			client_payload = self._get_client_payload_for_login()
		else:
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
		_l = self.ws.send_frame(payload=fin_msg.SerializeToString())


	def client_dump(self) -> str:
		""" repr of client object """
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


	def initiate_noise_handshake(self, login:bool=False):
		
		self._authenticate(self.WA_HEADER)

		self.ws.connect()
		self._rotate_signed_prekey()
		self._gen_signed_prekey()
		
		print(self.client_dump())

		self._authenticate(self.cephemeral_key.public.data)
		chello = msg_pb2.HandshakeMessage()
		chello.clientHello.ephemeral = self.cephemeral_key.public.data
		_l = self.ws.send_frame(intro_bytes=self.WA_HEADER, payload=chello.SerializeToString())

		# receive server hello
		recv_data = next(self.ws.recv_frame())
		shello = msg_pb2.HandshakeMessage()

		shello.ParseFromString(recv_data)
		self._process_server_hello(shello.serverHello)

		self._send_client_finish(login)


	def finish(self):
		"""
		create two AESGCM objects for encryption/decryption respectively
		"""
		_k = self._extract_with_salt_and_expand(self.salt, b"")
		self.ws.set_auth_keys(_k[:32], _k[32:])


	def logout(self):
		"""
		`logout` on Line #162985
		refs: `u()` on Line #57599
		"""
		_a =\
		wap.WapNode(
			tag = "iq", 
			attrs = {
				"to":wap.WapJid.create(user=None, server='s.whatsapp.net'), 
				"type":"set",
				"id": utils.generate_id(1),
				"xmlns": "md"
			},
			content = [wap.WapNode(
				tag="remove-companion-device",
				content=None,
				attrs={
					"jid": wap.WapJid.createJidU(user=self.username, device=self.device, domain_type=0),
					"reason": "user_initiated"
				}
			)]
		)
		print(_a)
		_buf = b'\x00' + wap.WapEncoder(_a).encode()
		enc = self.ws.noise_encrypt(_buf)
		self.ws.send_frame(payload=enc)


if __name__ == "__main__":
	
	client = Client(debug=False)
	client.initiate_noise_handshake()
	client.finish()
	srv_resp = next(client.ws.recv_frame())
	
	# refer to `_handleCiphertext on Line #11528
	dec = client.ws.noise_decrypt(srv_resp)
	assert len(dec) == 588

	dec_stream = utils.create_stream(dec)
	if int.from_bytes(dec_stream.read(1), 'big') & 2 != 0:
		print(f'might need to gzip inflate')
		raise NotImplementedError
	
	parsed_dec = wap.Y(dec_stream)
	#print(f"parsed id ~> {parsed_dec.attrs['id']}")
	ref_v = [parsed_dec.content[0].content[i].content for i in range(6)]
	ref = ref_v[0]

	_x = wap.WapNode(
		tag="iq", 
		content=None, 
		attrs = {
			"to": wap.WapJid.create(user=None, server='s.whatsapp.net'), 
			"type":'result', 
			"id": parsed_dec.attrs['id']
		}
	)

	_buf = b'\x00' +  wap.WapEncoder(_x).encode()
	enc = client.ws.noise_encrypt(_buf)
	client.ws.send_frame(payload=enc)

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

	# recieve servers reponse
	# expecting just a single response
	dec = client.ws.noise_decrypt(next(client.ws.recv_frame()))
	dec_stream = utils.create_stream(dec)
	dec_stream.read(1)
	resp_node = wap.Y(dec_stream)
	print(resp_node)

	client.username = resp_node.content[0].content[2].attrs['jid']._jid.user
	client.device = resp_node.content[0].content[2].attrs['jid']._jid.device

	# refer to source @ Line #47716
	adv_obj = msg_pb2.ADVSignedDeviceIdentityHMAC()
	adv_obj.ParseFromString(resp_node.content[0].content[1].content)
	computed_digest = hmac.digest(bd(client.adv_secret_key), adv_obj.details, 'sha256')
	print(f'digest>\n{computed_digest} \n{adv_obj.hmac}')

	# skip digest validation
	signed_dev_ident = msg_pb2.ADVSignedDeviceIdentity()
	signed_dev_ident.ParseFromString(adv_obj.details)

	#TODO
	# skip signature validation @ Line #47750

	# generate device signature
	# on line #58285
	buf = b'\x06\x01' + signed_dev_ident.details + client.cident_key.public.data\
	+ signed_dev_ident.accountSignatureKey
	signed_dev_ident.deviceSignature = curve.calculateSignature(secrets.token_bytes(64),\
	client.cident_key.private.data, buf)

	#TODO skip put identity in signal store

	dev_ident  = msg_pb2.ADVDeviceIdentity()
	dev_ident.ParseFromString(signed_dev_ident.details)
	x = dev_ident.keyIndex

	_ident = msg_pb2.ADVSignedDeviceIdentity()
	_ident.details = signed_dev_ident.details
	_ident.accountSignature = signed_dev_ident.accountSignature
	_ident.deviceSignature = signed_dev_ident.deviceSignature

	_f = _ident.SerializeToString()
	
	_x =\
	wap.WapNode(
		tag = "iq",
		attrs = {
			"to": wap.WapJid.create(user=None, server='s.whatsapp.net'),
			"type": "result",
			"id": resp_node.attrs['id']
		},
		content = [
			wap.WapNode(tag="pair-device-sign", 
				attrs={}, 
				content = [wap.WapNode(tag="device-identity", attrs={'key-index': str(x)}, content=_f)]
			)
		]
	)



	print(_x)
	t = wap.WapEncoder(_x).encode()
	_buf = b'\x00' + t

	enc = client.ws.noise_encrypt(_buf)
	client.ws.send_frame(payload=enc)


	for resp in client.ws.recv_frame():
		dec = client.ws.noise_decrypt(resp)
		t = utils.create_stream(dec)
		t.read(1)
		s = wap.Y(t)
		#print(s.attrs, s.tag, s.content)
		print(s)

	try:
		print(next(client.ws.recv_frame()))
	except Exception as e:
		print(':. disconnect detected')


	# make a new client and send upto the client finish message
	# get client payload for login @ Line #61560
	# ref _.setMe)(i) @ Line #47800
	
	client.reset_conn()
	client.initiate_noise_handshake(login=True)
	client.finish()
	srv_resp = next(client.ws.recv_frame())
	
	# refer to `_handleCiphertext on Line #11528
	dec = client.ws.noise_decrypt(srv_resp)
	# assert len(dec) == 588

	dec_stream = utils.create_stream(dec)
	if int.from_bytes(dec_stream.read(1), 'big') & 2 != 0:
		print(f'might need to gzip inflate')
		raise NotImplementedError
	
	parsed_dec = wap.Y(dec_stream)
	print(parsed_dec)
	time.sleep(5)
	client.logout()


	while True:
		for srv_resp in client.ws.recv_frame():
			# refer to `_handleCiphertext on Line #11528
			dec = client.ws.noise_decrypt(srv_resp)
			# assert len(dec) == 588
			dec_stream = utils.create_stream(dec)
			if int.from_bytes(dec_stream.read(1), 'big') & 2 != 0:
				print(f'might need to gzip inflate')
				raise NotImplementedError
			parsed_dec = wap.Y(dec_stream)
			print(parsed_dec)

