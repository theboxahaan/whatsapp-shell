import websocket
import _thread
import time
import rel
import msg_pb2
from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.dh.x25519.x25519 import X25519DH 
from dissononce.hash.sha256 import SHA256Hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from base64 import b64encode as be
import secrets
from Crypto.Cipher import AES


############### client session specific data ###################

g_counter = 0
pre_key_id = 1
noise_info_iv = [be(secrets.token_bytes(16)) for _ in range(3)]
recovery_token =  secrets.token_bytes(24)
cstatic_keys = X25519DH().generate_keypair()
aes_enc_key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
enc_object = AES.new(aes_enc_key, AES.MODE_CTR)

################################################################


def encrypt_noise_data(pyld, iv):
	pass

def authenticate(skey):
	pass

def shared_key(client_keypair, server_pub_key):
	server_pub_key = X25519DH().create_public(server_pub_key)
	print("generating the shared key")
	return X25519DH().dh(client_keypair, server_pub_key)

def signed_pre_shared_keygen(ident_key_privkey):
	client_pre_shared_privkey = Ed25519PrivateKey.generate()
	client_pre_shared_pubkey = client_pre_shared_privkey.public_key()
	pub_key_bytes = client_pre_shared_pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
	sig = ident_key_privkey.sign(pub_key_bytes)
	return client_pre_shared_privkey, client_pre_shared_pubkey, sig

def on_open(ws):
	print("Opened connection")
	
	client_eph_keys = X25519DH().generate_keypair()
	print("generated eph key-pair", client_eph_keys)
	# client_ident_keys = X25519DH().generate_keypair()
	client_ident_privkey = Ed25519PrivateKey.generate()
	client_ident_pubkey = client_ident_privkey.public_key()
	print("generated ident keys", client_ident_pubkey)
	
	reg_id = secrets.token_bytes(2)
	print("generated registration id")
	
	client_pre_shared_privkey, client_pre_shared_pubkey, sig = signed_pre_shared_keygen(client_ident_privkey)
	print("generated signed pre-shared-key of len ", len(sig))

	chello = msg_pb2.ClientHello()
	#chello.ephemeral = b'\xd6h\xe4\x95\x95g\xa9\xd0\x08\xc2\xc9\xaa\x84y\x02S\xc8\x91>\x8f\x11o\xf1t\xcc\x92\xd41_\xbe\xcc<'
	chello.ephemeral = client_eph_keys.public.data
	final_msg = b"\x57\x41\x06\x02\x00\x00\x24\x12\x22" + chello.SerializeToString()
	# final_msg = b'\x0a'
	print(f"The client hello message is ~> {final_msg.hex()}")
	ws.send_binary(final_msg)
	print("==========================")
	recvd_data = ws.recv_frame()
	print(len(recvd_data.data[6:]))
	#print(recvd_data.data.hex())
	shello = msg_pb2.ServerHello()
	print(recvd_data.data[6:10].hex())
	shello.ParseFromString(recvd_data.data[6:])
	print("static ", len(shello.static))
	print("ephemeral", len(shello.ephemeral))
	print("payload ", len(shello.payload))

	#TODO authenticate ephemeral key of the server	
	
	# generate the shared key
	shared_key(client_eph_keys, shello.ephemeral)
	


if __name__ == "__main__":
	websocket.enableTrace(True)
	ws = websocket.WebSocket()
	ws.connect("wss://web.whatsapp.com/ws/chat", header=["User-Agent: Chrome/100.0.4896.127"])
	on_open(ws)
	# ws.run_forever(dispatcher=rel)  # Set dispatcher to automatic reconnection
	rel.signal(2, rel.abort)  # Keyboard Interrupt
	rel.dispatch()
