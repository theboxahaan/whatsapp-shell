import websocket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import utils

class FrameSocket:
	"""
	class to handle websocket methods and coroutines
	"""
	websocket_url = "wss://web.whatsapp.com/ws/chat"
	header = ["User-Agent: Chrome/100.0.4896.127"]
	cookie_str = 'wa_lang_pref=en; wa_beta_version=production%2F1654038811%2F2.2220.8'
	host = "web.whatsapp.com"
	origin = "https://web.whatsapp.com"
	def __init__(self, ws:websocket=None, debug:bool=False):
		self.ws = ws
		self.noise_enc = None
		self.noise_dec = None
		self.noise_enc_ctr = 0
		self.noise_dec_ctr = 0

		if debug:
			websocket.enableTrace(True)


	def connect(self):
		"""
		opens a websocket connection with the server
		"""
		self.ws = websocket.WebSocket()
		self.ws.connect(self.websocket_url, header=self.header, origin=self.origin,\
		host=self.host, cookie=self.cookie_str)
	
	
	def send_frame(self, intro_bytes:bytes=None, payload:bytes=None) -> int:
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
	
	
	def recv_frame(self) -> bytes:
		"""
		generator
		receive `binary_frame` from server and parse it to return `data` bytes
		@return payload bytes
		"""
		pyld = self.ws.recv_frame()
		print(f'<- size: {len(pyld.data)}')
		if len(pyld.data) <= 4:
			return pyld.data
		recv_stream = utils.create_stream(pyld.data)
		while True:
			pyld_len = int.from_bytes(recv_stream.read(3), 'big')
			if pyld_len == 0:
				break
			else:
				yield recv_stream.read(pyld_len)


	def set_auth_keys(self, enc_key:bytes=None, dec_key:bytes=None):
		"""
		sets the encryption/decryption keys associated with the auth. websocket
		@arg enc_key: encryption key bytes
		@arg dec_key: decryption key bytes
		"""
		self.noise_enc, self.noise_dec = AESGCM(enc_key), AESGCM(dec_key)

	
	def noise_encrypt(self, pt:bytes=None) -> bytes:
		"""
		encrypt plaintext with the assoc data `None`
		@arg pt: plaintext bytes to encrypt
		@return encrypted bytes
		"""
		enc = self.noise_enc.encrypt(utils.gen_iv(self.noise_enc_ctr), pt, None) 
		self.noise_enc_ctr += 1
		return enc


	def noise_decrypt(self, ct:bytes=None) -> bytes:
		"""
		decrypt ciphertext with the assoc data `None`
		@arg ct: ciphertext bytes to decrypt
		@return decrypted bytes
		"""
		dec = self.noise_dec.decrypt(utils.gen_iv(self.noise_dec_ctr), ct, None)
		self.noise_dec_ctr+=1
		return dec


