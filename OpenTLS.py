import os
import socket
import sys
import binascii
import traceback
import itertools

from Crypto.Hash import *
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from KeyExchange import *
from Common import *
from Certificate import Certificate, load_root_CAs
from BlockCipher import AES_CBC, AES_GCM


TLS_HANDSHAKE 			= 22
TLS_APPLICATION_DATA 	= 23
TLS_CHANGE_CIPHER_SPEC 	= 20
TLS_ALERT				= 21

TLS_CLIENT_HELLO				= 1
TLS_SERVER_HELLO 				= 2
TLS_CERTIFICATE 				= 11
TLS_SERVER_KEY_EXCHANGE			= 12
TLS_SERVER_HELLO_DONE 			= 14
TLS_CLIENT_KEY_EXCHANGE			= 16

TLS_alert = {
	0: 'close_notify',
	10: 'unexpected_message',
	20: 'bad_record_mac', 
	21: 'decryption_failed', 
	22: 'record_overflow', 
	30: 'decompression_failure', 
	40: 'handshake_failure', 
	41: 'no_certificate', 
	42: 'bad_certificate', 
	43: 'unsupported_certificate', 
	44: 'certificate_revoked', 
	45: 'certificate_expired', 
	46: 'certificate_unknown', 
	47: 'illegal_parameter', 
	48: 'unknown_ca', 
	49: 'access_denied', 
	50: 'decode_error', 
	51: 'decrypt_error', 
	60: 'export_restriction', 
	70: 'protocol_version',
	71: 'insufficient_security',
	80: 'internal_error', 
	90: 'user_canceled', 
	100: 'no_renegotiation', 
	255: 'unsupported_extension'
}


############################################################################
# Cipher Suites
############################################################################

class CipherSuite:
	def __init__(self, name):
		self.name = name

# Instead of manually entering all the cipher suites details, we go through
# globals() to get the list of variables that look like cipher suites
# (TLS_..._WITH_...) and try to parse them to figure out the key exchange,
# key size, AES mode and authentication method

TLS_RSA_WITH_AES_128_CBC_SHA 			= '002f'
TLS_RSA_WITH_AES_128_CBC_SHA256			= '003c'
TLS_RSA_WITH_AES_256_CBC_SHA256			= '003d'
TLS_DHE_RSA_WITH_AES_128_CBC_SHA 		= '0033'
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 		= 'c013'
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 		= 'c014'
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	= 'c027'
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384	= 'c028'
#TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = '009e'
#TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 'c02f'

def parse_cipher_suite(name, code):
	global cipher_suites

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
		if 'WITH_AES_128_CBC_' in name or 'WITH_AES_256_CBC_':
			cipher_suite.block_cipher = AES_CBC
		elif 'WITH_AES_128_GCM_' in name or 'WITH_AES_256_GCM_':
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

	except:
		return

	cipher_suites[code] = cipher_suite

def init_cipher_suites():
	global cipher_suites

	cipher_suites = {}

	cipher_suite_variables = { name: value for (name, value) in globals().items() if name.startswith('TLS_') and '_WITH_' in name }
	
	for name, value in cipher_suite_variables.items():
		parse_cipher_suite(name, value)

init_cipher_suites()


############################################################################
# TLS
############################################################################

class TLS:
	def __init__(self, host, port=443, cipher=None):
		self.cipher_suite_code = cipher

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.ip = (host, port)
		self.handshake_messages = []

		try:
			self.sock.connect(self.ip)
			print("Connected to server: %s" % (self.ip,))
			self.send_client_hello()
			self.receive_server_hello()
			self.send_client_key_exchange()
			self.send_client_change_cipher_suite()
			self.send_client_encrypted_handshake()
			self.receive_server_end_handshake()
			self.sends_GET_request()
			self.receive_HTML_response()

		except socket.timeout as te:
			print("Failed to open connection to server: %s" % (self.ip,))
		except Exception as e:
			traceback.print_exc()
			print(e)
		finally:
			print('')
			print("Closing the connection")
			self.sock.close()

	def HMAC_hash(self, secret, val):
	    h = HMAC.new(secret, digestmod=self.PRF_hash)
	    h.update(val)
	    return h.digest()

	def P_hash(self, secret, seed, size):
	    A = seed
	    result = ''
	    while size > 0:
	        A = self.HMAC_hash(secret, A)
	        result += self.HMAC_hash(secret, A+seed)
	        size -= self.PRF_hash.digest_size
	        
	    return result

	def PRF(self, secret, label, seed, size):
	    return self.P_hash(secret, label+seed, size)[0:size]

	def handle_alert(self, msg):
		alert = "TLS Server Alert: " + TLS_alert[to_int(msg[1])]
		if msg[0] == '\x02':
			raise Exception(alert)
		else:
			print(alert)

	def TLS_record(self, content_type, message):
		return chr(content_type) + to_bytes(0x0303) + to_n_bytes(len(message), 2) + message


	# Client Hello message
	def send_client_hello(self):
		client_hello = '010001fc03035716eaceec93895c4a18d31c5f379bb305b432082939b83ee09f9a96babe0a400000'

		if self.cipher_suite_code is None:
			client_hello += to_hex(to_bytes(len(cipher_suites)*2)) + ''.join(cipher_suites.keys())
		else:
			client_hello += '02' + self.cipher_suite_code

		client_hello += '0100'
		client_hello = client_hello.decode('hex')

		self.client_random = client_hello[6:6+32]

		TLS_extension_renegotiation_info = 'ff01000100'.decode('hex')
		hostname_len = len(self.ip[0])
		TLS_extension_server_name = '\x00\x00' + to_n_bytes(hostname_len+5, 2) + to_n_bytes(hostname_len+3, 2) + '\x00' + to_n_bytes(hostname_len, 2) + self.ip[0]
		TLS_extension_signature_algorithms = '000d0012001006010603050105030401040302010203'.decode('hex')
		TLS_extension_ec_point_formats = '000b00020100'.decode('hex')
		TLS_extension_elliptic_curves = '000a0006000400170018'.decode('hex')

		TLS_extensions = \
			TLS_extension_renegotiation_info + \
			TLS_extension_server_name + \
			TLS_extension_signature_algorithms + \
			TLS_extension_ec_point_formats + \
			TLS_extension_elliptic_curves

		padding_length = 512 - 2 - len(client_hello) - len(TLS_extensions) - 4
		padding = '\x00\x15' + to_n_bytes(padding_length, 2) + '\x00' * padding_length

		client_hello = client_hello + to_n_bytes(512 - 2 - len(client_hello), 2) + TLS_extensions + padding

		self.handshake_messages.append(client_hello)
		msg = self.TLS_record(TLS_HANDSHAKE, client_hello)
		self.sock.sendall(msg)


	# Server Handshake messages (Server Hello, Certificates, Server Key Exchange, Server Hello Done)
	def receive_server_hello(self):
		bytes_expected = 0
		bytes_received = 0
		need_to_download_more = True

		server_msg = ''
		idx = 0

		while bytes_received < bytes_expected or need_to_download_more:
			msg = self.sock.recv(65536)
			server_msg += msg
			bytes_received += len(msg)

			while idx < bytes_received:
				size = to_int(server_msg[idx+3:idx+5])
				bytes_expected += size + 5
				while bytes_received < bytes_expected:
					msg = self.sock.recv(65536)
					server_msg += msg
					bytes_received += len(msg)

				if to_int(server_msg[idx]) == TLS_ALERT:
					self.handle_alert(server_msg[idx+5:idx+7])

#				print('Content type: %d' % to_int(server_msg[idx]))
	#			print('Size: ', size)
				subtype = to_int(server_msg[idx+5])
				subsize = to_int(server_msg[idx+6:idx+8])
	#			print('Subcontent type: %d' % subtype)
	#			print('Size: ', subsize)

				self.handshake_messages.append(server_msg[idx+5:idx+5+size])

				# We stop at the Server Hello Done
				if subtype == TLS_SERVER_HELLO_DONE:
					need_to_download_more = False

				idx += size + 5
	#			print('')

		server_hello = next(msg for msg in self.handshake_messages if msg[0] == chr(TLS_SERVER_HELLO))
		self.server_random = server_hello[6:6+32]
		server_key_exchange = next((msg for msg in self.handshake_messages if msg[0] == chr(TLS_SERVER_KEY_EXCHANGE)), None)
		server_certificate = next((msg for msg in self.handshake_messages if msg[0] == chr(TLS_CERTIFICATE)), None)
		if server_certificate is None:
			raise Exception('No SSL Certificate received from the server')

		self.certificate = Certificate(server_certificate[7:])

		session_ID_length = to_int(server_hello[38])

		cipher_suite_code = server_hello[39+session_ID_length:41+session_ID_length].encode('hex')
		self.cipher_suite = cipher_suites[cipher_suite_code]
		print('Cipher suite: ' + self.cipher_suite.name)
		self.key_exchange = self.cipher_suite.key_exchange(server_key_exchange if server_key_exchange is not None else self.certificate)
		self.PRF_hash = SHA384 if self.cipher_suite.msg_auth == SHA384 else SHA256

		# Verify the certificate
		# RSA key exchange, there is no key exchange parameters to verify
		if server_key_exchange is None:
			server_key_exchange = self.certificate
			self.certificate.verify(None, None, None, domain=self.ip[0])
		# Diffie-Hellman key exchange - start with verifying the key exchange parameters
		else:
			signed_data = self.client_random + self.server_random + server_key_exchange[4:-260]
			algo_code = server_key_exchange[-260]
			if algo_code == '\x06':
				algo = SHA512
			elif algo_code == '\x05':
				algo = SHA384
			elif algo_code == '\x04':
				algo = SHA256
			elif algo_code == '\x03':
				algo = SHA224
			elif algo_code == '\x02':
				algo = SHA
			else:
				algo = SHA
			self.certificate.verify(signed_data, signature=server_key_exchange[-256:], algo=algo, domain=self.ip[0])


	def send_client_key_exchange(self):
		self.premaster_secret = self.key_exchange.get_premaster_secret()
		client_key_exchange = self.key_exchange.get_client_key_exchange()

		self.handshake_messages.append(client_key_exchange)
		self.client_key_exchange_msg = self.TLS_record(TLS_HANDSHAKE, client_key_exchange)

		self.master_secret = self.PRF(to_bytes(self.premaster_secret), "master secret", self.client_random + self.server_random, 48)

		keys = self.PRF(self.master_secret, "key expansion", self.server_random + self.client_random, self.cipher_suite.msg_auth.digest_size*2 + 32 + 32)

		self.BlockCipher = self.cipher_suite.block_cipher(keys=keys, key_size=self.cipher_suite.key_size, hash=self.cipher_suite.msg_auth)


	def send_client_change_cipher_suite(self):
		self.client_change_cipher_spec_msg = self.TLS_record(TLS_CHANGE_CIPHER_SPEC, '01'.decode('hex'))


	def send_client_encrypted_handshake(self):
		handshake = ''.join(self.handshake_messages)
		h = self.PRF_hash.new()
		h.update(handshake)

		client_handshake_hash_computed = '\x14\x00\x00\x0c' + self.PRF(self.master_secret, "client finished", h.digest(), 12)
		self.handshake_messages.append(client_handshake_hash_computed)

		client_encrypted_handshake = self.BlockCipher.encrypt(client_handshake_hash_computed, seq_num=0, content_type=TLS_HANDSHAKE)
#										 encrypt(client_handshake_hash_computed, self.client_write_IV, self.client_write_key, self.client_write_MAC_key, 0, TLS_HANDSHAKE)
		client_encrypted_handshake_msg = self.TLS_record(TLS_HANDSHAKE, client_encrypted_handshake)

		self.sock.sendall(self.client_key_exchange_msg + self.client_change_cipher_spec_msg)
		self.sock.sendall(client_encrypted_handshake_msg)

	# Server Change Cipher Spec and Server Encrypted Handhsake message
	# (ignored right now except for TLS Alert)
	def receive_server_end_handshake(self):
		server_msg = self.sock.recv(65536)
		idx = 0
		bytes_received = len(server_msg)

		while idx < bytes_received:
			size = to_int(server_msg[idx+3:idx+5])

#			print('Content type: %d' % to_int(server_msg[idx]))

			if to_int(server_msg[idx]) == TLS_ALERT:
				self.handle_alert(server_msg[idx+5:idx+7])

			idx += size + 5			


	def sends_GET_request(self):
		plaintext = 'GET / HTTP/1.1\r\nHOST: ' + self.ip[0] + '\r\n\r\n'
		print("Sending [" + plaintext + "]")
		ciphertext = self.BlockCipher.encrypt(plaintext, seq_num=1, content_type=TLS_APPLICATION_DATA)

		client_data_msg = self.TLS_record(TLS_APPLICATION_DATA, ciphertext)
		self.sock.sendall(client_data_msg)

	def receive_HTML_response(self):
		print('')
		data = []
		app_data = ''
		plaintext_downloaded = 0

		bytes_expected = 0
		bytes_received = 0
		need_to_download_more = True
		content_length = None

		idx = 0
		seq_num = 1

		while bytes_received < bytes_expected or need_to_download_more:
			msg = self.sock.recv(65536)
			app_data += msg
			bytes_received += len(msg)

			while idx < bytes_received:
				size = to_int(app_data[idx+3:idx+5])
	#			print('Size: %d' % size)
				bytes_expected += size + 5
				while bytes_received < bytes_expected:
					msg = self.sock.recv(65536)
					app_data += msg
					bytes_received += len(msg)

				# Decrypt
				plaintext = self.BlockCipher.decrypt(app_data[idx+5:idx+5+size], seq_num=seq_num, content_type=TLS_APPLICATION_DATA)
				seq_num += 1

				if content_length is None:
					length_start_idx = plaintext.find('Content-Length:')
					start = plaintext.find('\r\n\r\n')

					if length_start_idx < 0:
						try:
							start += 4
							end = plaintext.find('\r\n', start)
							size_hex = plaintext[start:end]
							if (len(size_hex) % 2 == 1):
								size_hex = '0' + size_hex
							content_length = to_int(size_hex.decode('hex'))
							start = end
						except:
							print(plaintext)
							return

					else:
						length_start_idx += 15
						length_end_idx = plaintext.find('\r\n', length_start_idx)
						content_length = int(plaintext[length_start_idx:length_end_idx])

					total_length = start + content_length

				data.append(plaintext)
				plaintext_downloaded += len(plaintext)

				if plaintext_downloaded >= content_length:
					need_to_download_more = False

				idx += size + 5
				print('')

		for plaintext in data:
			print(plaintext)


########################################################################

f = open('root_certificates.pem')
root_CAs = f.read()
f.close()

load_root_CAs(root_CAs)

hostname = None
port = 443
cipher = None

is_next = 'hostname'

for arg in sys.argv[1:]:
	if arg == '-cipher' or arg == '-c':
		is_next = 'cipher'
	else:
		if is_next == 'hostname':
			hostname = arg
			is_next = port
		elif is_next == 'port':
			port = int(arg)
			is_next = None
		elif is_next == 'cipher':
			cipher = next((k for k, c in cipher_suites.items() if c.name == arg), None)
			if cipher is None:
				print('Unknown cipher suite: %s' % arg)
				print('')
				print("Cipher suites supported:")
				for cipher in cipher_suites.itervalues():
					print('- ' + cipher.name)
				print('')				
				quit()
			is_next = 'hostname'

if hostname is None:
	print('%s [-cipher <cipher suite>] <hostname> [port]' % sys.argv[0])
	print('')
	print("Cipher suites supported:")
	for cipher in cipher_suites.values():
		print('- ' + cipher.name)
	print('')	
	quit()

t = TLS(hostname, port, cipher)
