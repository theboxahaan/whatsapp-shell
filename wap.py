import io
from types import SimpleNamespace
import json
import math

class WAPJID:
	def __init__(self, w_type, w_user, w_server):
		self.type = w_type
		self.user = w_user
		self.server = w_server

class class_o:
	def __init__(self, jid:WAPJID=None):
		self._jid = jid

class class_M:
	def __init__(self, tag:str=None, attrs:dict=None, content=None):
		self.tag = tag
		self.attrs = attrs
		self.content = content
	#def __repr__(self):
	#	return f'{"+"*50}\ntag > {self.tag}\nattrs > {self.attrs}\ncontent > {self.content}'\
	#	+ f'\n{"+"*50}'

def D(e,t:io.BytesIO=None):
	'''
	function `D(e,t)` at Line #10764
	'''
	if e.tag is None:
		t.write(b'\xf8')
		t.write(b'\x00')
		print('tag is none')
		return
	n = 1
	if e.attrs is not None:
		n += 2*len(e.attrs.keys())
	if e.content is not None:
		n += 1
	if n < 256:
		t.write(b'\xf8')
		t.write(n.to_bytes(1, 'big'))
	else:
		if n < 65536:
			t.write(b'\xf9')
			t.write(n.to_bytes(2, 'big'))
	N(e.tag, t)
	print(':. wrote the tag to the buffer', e.attrs.keys())
	if e.attrs is not None:
		for n in e.attrs.keys():
			G(n, t)
			N(e.attrs[n], t)
	r = e.content
	if isinstance(r, bytes):
		if len(r) < 256:
			t.write(b'\xf8')
			t.write(len(r).to_bytes(1, 'big'))
		else:
			if len(r) < 65536:
				t.write(b'\xf9')
				t.write(len(r).to_bytes(2, 'big'))
		for e in range(len(r)):
			D(r[e] ,t)
	else:
		if r is not None:
			N(r, t)


def x():
	pass

L = None
k = None

def G(e, t):
	'''
	function `G(e, t)` on Line #10798
	'''
	if e == "":
		t.write(b'\xfc')
		t.write(b'\x00')
		return
	#if L is None:
	L = {_L.SINGLE_BYTE_TOKEN[k]:k for k in range(len(_L.SINGLE_BYTE_TOKEN))}
	n = L.get(e, None)
	if n is not None:
		# print(f'writing {n+1} to the buffer')
		t.write((n+1).to_bytes(1, 'big'))
		return
	#if k is None:
	k = []
	for entry in _L.DICTIONARIES:
		k.append({entry[i]:i for i in range(len(entry))})

	for n in range(len(k)):
		r = k[n].get(e, None)
		if r is not None:
			h = [236, 237, 238, 239]
			t.write(h[n].to_bytes(1, 'big'))
			t.write(r.to_bytes(1, 'big'))
			return
	
	r = len(e)		# replace numUtf8Bytes
	if r < 128:
		#FIXME skipping the regex check assume `True` both times
		# function B(e, t, n) @Line #10827 --- B(e,255,t)
		def B(e,t,n):
			r = (len(e) % 2) == 1
			n.write(t.to_bytes(1, 'big'))
			i = math.ceil(len(e) /2)
			if r:
				i |= 128
			n.write(i.to_bytes(1, 'big'))
			a = 0
			for r in range(len(e)):
				i = ord(e[r])
				o = None
				# long ass if condition which if True, raise Error `Cannot nibble encode`
				if 48 <= i and i <= 57:
					o = i-48
				else:
					if t == 255:
						if i == 45:
							o = 10
						else:
							if i == 46:
								o = 1
					else:
						if t == 251 and 65 <= i and i <= 70:
							o = i - 75
				if o is None:
					print('Cannot nibble encode')
				if r % 2 == 0:
					a = o << 4
					if r == len(e) - 1:
						a |= 15
						n.write(a.to_bytes(1, 'big'))
				else:
					a |= o
					n.write(a.to_bytes(1, 'big'))
		B(e, 255, t)
		return
	#FIXME
	# this should not be called atleast till the handshake is complete 
	x(r, t)
	# t.writeString(e)

def N(e, t:io.BytesIO=None):
	# print(f'e > {e}')
	if e is None:
		t.write(b'\x00')
	elif isinstance(e, class_M):
		D(e,t)
	elif isinstance(e, class_o):
		n = e._jid
		if n.type == _C.WAP_JID_SUBTYPE.JID_U:
			raise NotImplementedError
		elif n.type == _C.WAP_JID_SUBTYPE.JID_FB:
			raise NotImplementedError
		else:
			t.write(int(250).to_bytes(1, 'big'))
			if n.user is not None:
				N(n.user, t)
			else:
				t.write(int(0).to_bytes(1, 'big'))
			N(n.server, t)
	elif isinstance(e, str):
		G(e,t)
	else:
		if not isinstance(e, bytes):	# standin for Uint8Array
			print('invalid payload type')
		def x(e:int, t:io.BytesIO):
			raise NotImplemented
		x(len(e), t)
		t.write(e)


def rshift(val, n): 
	"""
	source: https://stackoverflow.com/questions/5832982/how-to-get-the-logical-right-binary-shift-in-python
	"""
	return (val % 0x100000000) >> n

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
	# print('extra> ', extra)
	if extra is not None:
		return e.read(t).decode('utf-8')
	else:
		return e.read(t)


def F(e:io.BytesIO=None, t:bool=None):
	'''
	function `F(e,t)` on Line #10862
	'''
	n = int.from_bytes(e.read(1), 'big')
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
	if not isinstance(t, str):
		print('decode string got invalid argument')
	return t


def M(e, *args):
	'''
	class at Line #10665
	'''
	if len(args) > 0:
		t = args[0]
	else:
		t = {}
	if len(args) > 1:
		n = args[1]
	else:
		n = None
	return class_M(tag=e, attrs=t, content=n)


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
	#print(f'r > {r}')
	#print(f'i > {i}')
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