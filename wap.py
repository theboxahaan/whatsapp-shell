import io
from types import SimpleNamespace
import json

def rshift(val, n): 
	"""
	source: https://stackoverflow.com/questions/5832982/how-to-get-the-logical-right-binary-shift-in-python
	"""
	return (val % 0x100000000) >> n

class WAPJID:
	def __init__(self, w_type, w_user, w_server):
		self.type = w_type
		self.user = w_user
		self.server = w_server

class WapJid:
	def __init__(self):
		pass	
	
	@staticmethod
	def create(e, t):
		return WAPJID(0, None, t)

	@staticmethod
	def createAD():
		pass
	
	@staticmethod
	def createFbJid():
		pass
	
	@staticmethod
	def createJidU():
		pass

_E = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']


_C = SimpleNamespace(**{
	'DOMAIN_TYPE': SimpleNamespace(**{
		'LID': 1,
		'WHATSAPP': 0
	}),
	'WAP_JID_SUBTYPE': SimpleNamespace(**{
		'JID': 0,
		'JID_AD': 1,
		'JID_FB': 3,
		'JID_U': 1
	}),
	'WapJid': WapJid
})

with open('L_act.json', 'r') as fd:
	_j = json.load(fd)

_L = SimpleNamespace(**{
	'DICTIONARIES': _j['DICTIONARIES'],
	'SINGLE_BYTE_TOKEN': _j['SINGLE_BYTE_TOKEN']
})


def j(e:io.BytesIO=None, t:int=None):
	'''
	function `j` at Line #10943
	'''
	n = []
	for i in range(t):
		n.append(Y(e))
	return n


def H(e, t, n, r):
	'''
	function `H(e,t,n,r)` defined at Line #10985
	'''
	i = [None for _ in range(2*r - n) ]
	for n in range(0, len(i) - 1, 2):
		r = int.from_bytes(e.read(1), 'big')
		i[n] = t[rshift(r, 4)]
		i[n+1] = t[15 & r]
	if n:
		n = int.from_bytes(e.read(1), 'big')
		i[len(i) - 1] = t[rshift(n , 4)]
	return "".join(i)


def W(e, t, extra:bool):
	'''
	function at Line #10980
	'''
	print('extra> ', extra)
	if extra is not None:
		return e.read(t).decode('utf-8')
	else:
		return e.read(t)


def F(e:io.BytesIO=None, t:bool=None):
	'''
	function `F(e,t)` on Line #10862
	'''
	n = int.from_bytes(e.read(1), 'big')
	print(n)
	if n == 0:
		return None
	if n == 248:
		return j(e, int.from_bytes(e.read(1), 'big'))
	if n == 249:
		return j(e, int.from_bytes(e.read(2), 'big'))
	if n == 252:
		n = int.from_bytes(e.read(1), 'big')
		return W(e, n, t)
	if n == 253:
		n = int.from_bytes(e.read(1), 'big')
		r = int.from_bytes(e.read(1))
		i = int.from_bytes(e.read(1))
		return W(e, ((15 & n) << 16) + (r << 8) + i, t)
	if n == 254:
		n = int.from_bytes(e.read(4), 'big')
		return W(e, n, t)
	if n == 250:
		t = F(e, True)
		if not isinstance(t, str) and t is not None:
			print('decode string got invalid value')
			print('error ->', t)
		n = K(e)
		return _C.WapJid.create(t, n)
	if n == 246:
		print('yet to implement 246')
		raise NotImplementedError
	if n == 247:
		# returns a val but does so weirdly
		n = int.from_bytes(e.read(1), 'big')
		if n == 0:
			t = _C.DOMAIN_TYPE.WHATSAPP
		else:
			if n != 1:
				print('decode JidU error')
			t = _C.DOMAIN_TYPE.LID
		r = int.from_bytes(e.read(1), 'big')
		i = K(e)
		return _C.WapJid.createJidU(i, t, r)
	if n == 255:
		t = int.from_bytes(e.read(1), 'big')
		print('need to implement >>>')
		#return H(e, E, t )
		return None
	if n == 251:
		t = int.from_bytes(e.read(1), 'big')
		return H(e, _E, rshift(t, 7), 127 & t)
	if n <=0 or n >=240:
		print('unable to decode WAPBuffer')
	if n >=236 and n <=239:
		t = n - 236
		r = _L.DICTIONARIES[t]
		if r is None:
			print('Missing WAP dict')
		i = int.from_bytes(e.read(1), 'big')
		a = r[i]
		if a is None:
			print('invalid value index')
		return a
	r = _L.SINGLE_BYTE_TOKEN[n-1]
	if r is None:
		print('undefined token')
	return r



def K(e:io.BytesIO=None):
	t = F(e, True)
	print(f'K>{t}')
	if not isinstance(t, str):
		print('decode string got invalid argument')
	return t


def M(e, *args):
	'''
	class at Line #10665
	'''
	print(f'arglen > {len(args)}')
	if len(args) > 0:
		t = args[0]
	else:
		t = {}
	if len(args) > 1:
		n = args[1]
	else:
		n = None
	return SimpleNamespace(tag=e, attrs=t, content=n)


def Y(e:io.BytesIO=None):
	"""
	function `Y(e)` on Line #10949
	"""
	t = int.from_bytes(e.read(1), 'big')
	if t == 248:
		n = int.from_bytes(e.read(1), 'big')
	else:
		if t != 249:
			print('type byte is invalid')
		n = int.from_bytes(e.read(2), 'big')
	if n == 0:
		print('failed to decode node')
	
	a = K(e)
	r = {}
	n -= 1
	while n > 1:
		t = K(e)
		i = F(e, True)
		r[t] = i
		n -= 2
	assert n == 1
	i = F(e, False)
	# assert something else ... dont care for now
	print(f'r > {r}')
	print(f'i > {i}')
	return M(a,r,i)


def create_stream(e:bytes=None):
	"""
	convert a bytes type object into a byte-stream with a `read` method
	"""
	stream = io.BytesIO(e)
	return stream

if __name__ == '__main__':
	s = create_stream(b'1234567890')
	for _ in range(10):
		print(s.read(1))
