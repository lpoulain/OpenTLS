import base64

from Crypto.Hash import *
from Common import *


RSA_algorithms = {
    sha1WithRSAEncryption: SHA,
    sha256WithRSAEncryption: SHA256,
    sha384WithRSAEncryption: SHA384,
}

root_CA = { }

def add_root_CA(certificate):
#	print(name)
	try:
		tree, _ = ASN1(certificate)
		name = tree[0][5][-1][0][1]

		publicKey = tree[0][6][1][0]
		if publicKey[0] == '\x00':
			publicKey = publicKey[1:]

		h = SHA256.new()
		h.update(publicKey)

		root_CA[h.digest()] = to_int(publicKey)
	except:
		pass

def load_root_CAs(body):
	lines = body.split('\n')

	status = None

	for line in lines:
		if status is None and line == '-----BEGIN CERTIFICATE-----':
			status = 'capture'
			certificate = ''
		elif status == 'capture' and line != '-----END CERTIFICATE-----':
			certificate += line
		elif status == 'capture' and line == '-----END CERTIFICATE-----':
			add_root_CA(base64.b64decode(certificate))
			status = None

def ASN1(body):
	content_type = body[0]

#	print('Content type: 0x' + to_hex(content_type))

	# null
	if content_type == '\x05':
		return (0x00, 2)

	# A0
	if content_type == '\xA0':
		size = to_int(body[1])
		elt, offset = ASN1(body[2:2+size])
		return ([ elt ], 2 + size)

	size = to_int(body[1])	
	if size > 128:
		size -= 128
		offset = 2 + size
		size = to_int(body[2:2+size])
	else:
		offset = 2

	# number, object identifier, UTF8string, printable string, UTC time
	if content_type in ['\x02', '\x06', '\x0C', '\x13', '\x17']:
#		print("Number: " + to_hex(body[offset:offset+size]) + ' (' + str(offset + size) + ')')
		return (body[offset:offset+size], offset + size)

	# octet string, bit string
	if content_type in ['\x13', '\x03', '\xA3']:
		if body[offset] == '\x00':
			offset += 1
			size -= 1
		elt, _ = ASN1(body[offset:offset+size])
		return (elt, offset + size)

	# sequence, set
	if content_type in ['\x30', '\x31']:
		elements = []
		pos = offset
		size += offset

		while pos < size:
			elt, offset = ASN1(body[pos:])
			pos += offset
			elements.append(elt)

		return (elements, size)

	return (body, len(body))


class Certificate:
	def __init__(self, certificates):
		size = to_int(certificates[0:3])
		certificate = certificates[3:3+size]
		self.body, _ = ASN1(certificate)
		size_signed_data = to_int(certificate[6:8])
		self.signed_data = certificate[4:8+size_signed_data]
		self.RSA_n = to_int(self.body[0][6][1][0])
		self.RSA_e = to_int(self.body[0][6][1][1])
		self.domain = self.body[0][5][-1][0][1]
		self.signature = self.body[2]
		self.algorithm = self.body[1][0]

		if len(certificates) > size + 3:
			self.next = Certificate(certificates[3+size:])
		else:
			self.next = None

	def verify_signature(self, signed_data, signature, signature_algo):
		hash_size = signature_algo.digest_size
		hash1 = to_bytes(pow(to_int(signature), self.RSA_e, self.RSA_n))[-hash_size:]
		h = signature_algo.new()
		h.update(signed_data)
		hash2 = h.digest()

		if hash1 != hash2:
			print("Certificate signature failure:")
			print(to_hex(hash1))
			print(to_hex(hash2))
			return False

		return True

	def verify(self, signed_data, signature, algo, domain=None):
#		algo = RSA_algorithms[algo]

		print("SSL Certificate: " + self.domain)

		if domain is not None:
			if self.domain.split('.')[0] == '*':
				self.domain = '.'.join(self.domain.split('.')[1:])
				domain = '.'.join(domain.split('.')[1:])

#			if self.domain != domain:
#				raise Exception("Error: wrong domain: %s != %s" % (self.domain, domain))

		if self.algorithm not in RSA_algorithms:
			raise Exception("Unknown SSL Certificate verification algorithm: %s" % to_hex(self.algorithm))

		if signed_data is not None:
			self.verify_signature(signed_data, signature, algo)

		# If there is a parent Certificate, verify it
		if self.next is not None:
			self.next.verify(self.signed_data, self.signature, RSA_algorithms[self.algorithm])
			return
		
#			algo = RSA_algorithms[self.algorithm]
#			self.verify_signature(self.signed_data, self.signature, algo)

		# We have reached the root CA
		h = SHA256.new()
		h.update(to_bytes(self.RSA_n))
		hash = h.digest()
		
		if hash not in root_CA:
			print("WARNING: Root CA unknown: " + self.domain)
			return
		
		if self.RSA_n != root_CA[hash]:
			print("WARNING: Wrong Root CA")
#			print(to_hex(self.signed_data))
#			print(to_hex(root_CA[hash]))
