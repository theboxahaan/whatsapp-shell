import io
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from typing import Union

def get_Ed25519Key_bytes(key:Union[Ed25519PublicKey, Ed25519PrivateKey]=None) -> bytes:
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


def gen_iv(counter:int=None) -> bytes:
	"""
	convert a counter int into a 96 bit vector but strangely only the last 4 bytes
	are ever used
	#TODO check what happens when counter > 4 bytes 
	"""
	return b"\x00\x00\x00\x00\x00\x00\x00\x00" + counter.to_bytes(4, "big")


def create_stream(buffer:bytes=None) -> io.BytesIO:
	"""
	convert a bytes type object into a byte-stream with a `read` method
	@arg buffer: create a stream from the given buffer
	@return `BytesIO` stream
	"""
	stream = io.BytesIO(e)
	return stream
