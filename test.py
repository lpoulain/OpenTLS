import unittest
from OpenTLS import TLS

class TLSTest(unittest.TestCase):

	def use_cipher_suite(self, cipher_suite):
		t = TLS("www.wikipedia.org", 443, cipher_suite)
		self.assertTrue("<html" in t.response)

	def test_TLS_RSA_WITH_AES_128_CBC_SHA(self):
		self.use_cipher_suite('002f')

	def test_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(self):
		self.use_cipher_suite('0067')

	def test_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(self):
		self.use_cipher_suite('c014')

	def test_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(self):
		self.use_cipher_suite('c030')

if __name__ == '__main__':
	unittest.main()
