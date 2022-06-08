from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
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
