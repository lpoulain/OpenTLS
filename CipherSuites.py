from KeyExchange import *
from BlockCipher import AES_CBC, AES_GCM

class CipherSuite:
	def __init__(self, name):
		self.name = name

# Instead of manually entering all the cipher suites details, we go through
# globals() to get the list of variables that look like cipher suites
# (TLS_..._WITH_...) and try to parse them to figure out the key exchange,
# key size, AES mode and authentication method

TLS_RSA_WITH_AES_128_CBC_SHA 			= '002f'
TLS_RSA_WITH_AES_256_CBC_SHA 			= '0035'
TLS_RSA_WITH_AES_128_CBC_SHA256			= '003c'
TLS_RSA_WITH_AES_256_CBC_SHA256			= '003d'
TLS_RSA_WITH_AES_128_GCM_SHA256 		= '009c'
TLS_RSA_WITH_AES_256_GCM_SHA384 		= '009d'
TLS_DHE_RSA_WITH_AES_128_CBC_SHA 		= '0033'
TLS_DHE_RSA_WITH_AES_256_CBC_SHA 		= '0039'
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 	= '0067'
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 	= '006B'
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 	= '009e'
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 	= '009f'
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 		= 'c013'
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 		= 'c014'
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	= 'c027'
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384	= 'c028'
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 	= 'c02f'
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 	= 'c030'

class CipherSuites:

	def parse_cipher_suite(self, name, code):

		cipher_suite = CipherSuite(name)

		try:
			# Exchange key
			if name.startswith('TLS_RSA_WITH'):
				cipher_suite.key_exchange = RSA_Key_Exchange
			elif name.startswith('TLS_DHE_RSA_WITH'):
				cipher_suite.key_exchange = DHE_RSA_Key_Exchange
			elif name.startswith('TLS_ECDHE_RSA_WITH'):
				cipher_suite.key_exchange = ECDHE_RSA_Key_Exchange
			else:
				raise Exception("Unknown key exchange in cipher suite " + name)

			# Key size
			if 'WITH_AES_128_' in name:
				cipher_suite.key_size = 128
			elif 'WITH_AES_256_' in name:
				cipher_suite.key_size = 256
			else:
				raise Exception("Unknown key size in cipher suite " + name)

			# Block Cipher
			if 'WITH_AES_128_CBC_' in name or 'WITH_AES_256_CBC_' in name:
				cipher_suite.block_cipher = AES_CBC
			elif 'WITH_AES_128_GCM_' in name or 'WITH_AES_256_GCM_' in name:
				cipher_suite.block_cipher = AES_GCM
			else:
				raise Exception('Unknown block cipher in cipher suite ' + name)

			# Message authentication
			if name.endswith('_SHA'):
				cipher_suite.msg_auth = SHA
			elif name.endswith('_SHA256'):
				cipher_suite.msg_auth = SHA256
			elif name.endswith('_SHA384'):
				cipher_suite.msg_auth = SHA384
			else:
				raise Exception("Unknown message authentication in cipher suite " + name)

		except Exception as e:
			print(e)
			return

		self.cipher_suites[code] = cipher_suite

	def __init__(self):
		self.cipher_suites = {}

		cipher_suite_variables = { name: value for (name, value) in globals().items() if name.startswith('TLS_') and '_WITH_' in name }
		
		for name, value in cipher_suite_variables.items():
			self.parse_cipher_suite(name, value)

	def all(self):
		return self.cipher_suites

	def get(self, code):
		return self.cipher_suites[code]

	def items(self):
		return self.cipher_suites.items()

	def values(self):
		return self.cipher_suites.values()

	def itervalues(self):
		return self.cipher_suites.itervalues();

	def keys(self):
		return self.cipher_suites.keys()

	def count(self):
		return len(self.cipher_suites)
