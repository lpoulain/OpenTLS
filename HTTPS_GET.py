import os
import socket
import sys
import binascii
import tinyec.ec as ec
import tinyec.registry as reg

from Crypto.Hash import *
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

# TLS 1.2
TLS_VERSION				= '\x03\x03'

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

def to_int(str):
    return int(binascii.hexlify(str), 16)

def to_hex(str):
    return binascii.hexlify(str)

def nb_to_hex(nb, size):
    s = to_bytes(nb)
    return '\x00' * (size - len(s)) + s

def to_bytes(n):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).decode('hex')
    return s

def to_n_bytes(number, size):
	h = '%x' % number
	s = ('0'*(size*2 - len(h)) + h).decode('hex')
	return s

def Hash(data):
    h = SHA256.new()
    h.update(data)
    return h.digest()

def HMAC_hash(secret, val):
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(val)
    return h.digest()

def P_hash(secret, seed, size):
    A = seed
    result = ''
    while size > 0:
        A = HMAC_hash(secret, A)
        result += HMAC_hash(secret, A+seed)
        size -= 20
        
    return result

def PRF(secret, label, seed, size):
    return P_hash(secret, label+seed, size)[0:size]

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

	# ????
	return (body, len(body))


############################################################################
# AES 128-bit CBC encryption
############################################################################

def decrypt(message, key_AES, key_MAC, seq_num, content_type, debug=False):
	iv = message[0:16]
	cipher = AES.new(key_AES, AES.MODE_CBC, iv)
	decoded = cipher.decrypt(message[16:])

	padding = to_int(decoded[-1:]) + 1
	plaintext = decoded[0:-padding-20]
	mac_decrypted = decoded[-padding-20:-padding]

	hmac = HMAC.new(key_MAC, digestmod=SHA)
	plaintext_to_mac = to_n_bytes(seq_num, 8) + to_n_bytes(content_type, 1) + '\x03\x03' + to_n_bytes(len(plaintext), 2) + plaintext
	hmac.update(plaintext_to_mac)
	mac_computed = hmac.digest()

	if debug:
		print('Plaintext: [' + plaintext + ']')
		print('MAC (decrypted): ' + to_hex(mac_decrypted))
		print('MAC (computed):  ' + to_hex(mac_computed))
		print('')

	return plaintext


def encrypt(plaintext, iv, key_AES, key_MAC, seq_num, content_type):
    hmac = HMAC.new(key_MAC, digestmod=SHA)
    plaintext_to_mac = to_n_bytes(seq_num, 8) + to_n_bytes(content_type, 1) + '\x03\x03' + to_n_bytes(len(plaintext), 2) + plaintext
    hmac.update(plaintext_to_mac)
    mac_computed = hmac.digest()

    cipher = AES.new(key_AES, AES.MODE_CBC, iv)
    plaintext += mac_computed
    padding_length = 16 - (len(plaintext) % 16)
    if padding_length == 0:
    	padding_length = 16

    padding = chr(padding_length - 1) * padding_length
#    print(to_hex())
    ciphertext = cipher.encrypt(plaintext + padding)

    return ciphertext


############################################################################
# Key Exchange
############################################################################

elliptic_curves = {
	"0017": "secp256r1",
	"0018": "secp384r1"
}

class RSA_Key_Exchange:
	def __init__(self, certificates):
		cert_size = to_int(certificates[7:10])
		print('cert size: ', cert_size)
		certificate, _ = ASN1(certificates[10:10+cert_size])

		self.RSA_n = to_int(certificate[0][6][1][0])
		self.RSA_e = to_int(certificate[0][6][1][1])

	def get_premaster_secret(self):
		self.premaster_secret = TLS_VERSION + os.urandom(46)
		return to_int(self.premaster_secret)

	def get_client_key_exchange(self):
		premaster_secret = '\x00\x02' + '\x42' * (256 - 3 - len(self.premaster_secret)) + '\x00' + self.premaster_secret
		
		encrypted_premaster_secret = pow(to_int(premaster_secret), self.RSA_e, self.RSA_n)
		msg = '100001020100'.decode('hex') + to_bytes(encrypted_premaster_secret)
		return msg


class DHE_RSA_Key_Exchange:
	def __init__(self, server_key_exchange):
		self.p = to_int(server_key_exchange[6:6+256])
		self.y_s = to_int(server_key_exchange[11+256:11+512])
		self.g = 2L
	
	def get_premaster_secret(self):
		self.x = 'aedebc6285eb3c2a8b949bf3c89d5ab93ef67b13aaa2e6a4b849b48d07889ee7'.decode('hex')
		self.y_c = pow(self.g, to_int(self.x), self.p)
		self.premaster_secret = pow(self.y_s, to_int(self.x), self.p)
		return self.premaster_secret

	def get_client_key_exchange(self):
		client_key_exchange = '100001020100'.decode('hex') + to_bytes(self.y_c)
		return client_key_exchange

class ECDHE_RSA_Key_Exchange:
	def __init__(self, server_key_exchange):
		curve_code = server_key_exchange[5:7].encode('hex')
		print('Elliptic curve: ' + elliptic_curves[curve_code])
		self.curve = reg.get_curve(elliptic_curves[curve_code])
		x = to_int(server_key_exchange[9:9+32])
		y = to_int(server_key_exchange[9+32:9+64])
		self.server_pubKey = ec.Point(self.curve, x, y)

	def get_premaster_secret(self):
		self.client_secret = 0xaedebc6285eb3c2a8b949bf3c89d5ab93ef67b13aaa2e6a4b849b48d07889ee7
		self.client_pubKey = self.curve.g * self.client_secret

		secret = self.server_pubKey * self.client_secret
		return secret.x

	def get_client_key_exchange(self):
		client_key_exchange = '100000424104'.decode('hex') + to_n_bytes(self.client_pubKey.x, 32) + to_n_bytes(self.client_pubKey.y, 32)
		return client_key_exchange

############################################################################
# TLS
############################################################################

TLS_RSA_WITH_AES_128_CBC_SHA 		= '002f'
TLS_DHE_RSA_WITH_AES_128_CBC_SHA 	= '0033'
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA	= 'c013'

cipher_suites = {
	TLS_RSA_WITH_AES_128_CBC_SHA: ('TLS_RSA_WITH_AES_128_CBC_SHA', RSA_Key_Exchange),
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA: ('TLS_DHE_RSA_WITH_AES_128_CBC_SHA', DHE_RSA_Key_Exchange),
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: ('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', ECDHE_RSA_Key_Exchange),
}

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

class TLS:
	def __init__(self, host, port=443):
		self.supported_cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA

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
			print(e)
		finally:
			print('')
			print("Closing the connection")
			self.sock.close()

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
		client_hello = ('010001fc03035716eaceec93895c4a18d31c5f379bb305b432082939b83ee09f9a96babe0a40000006' + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + TLS_DHE_RSA_WITH_AES_128_CBC_SHA + TLS_RSA_WITH_AES_128_CBC_SHA + '0100').decode('hex')
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
		print(len(client_hello))
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
		server_key_exchange = next((msg for msg in self.handshake_messages if msg[0] == chr(TLS_SERVER_KEY_EXCHANGE)), None)
		if server_key_exchange is None:
			server_key_exchange = next((msg for msg in self.handshake_messages if msg[0] == chr(TLS_CERTIFICATE)))

		self.server_random = server_hello[6:6+32]
		session_ID_length = to_int(server_hello[38])
		chosen_cipher_suite = server_hello[39+session_ID_length:41+session_ID_length].encode('hex')
		print('Cipher suite: ' + cipher_suites[chosen_cipher_suite][0])
		self.key_exchange = cipher_suites[chosen_cipher_suite][1](server_key_exchange)

	def send_client_key_exchange(self):
		self.premaster_secret = self.key_exchange.get_premaster_secret()
		client_key_exchange = self.key_exchange.get_client_key_exchange()

		self.handshake_messages.append(client_key_exchange)
		self.client_key_exchange_msg = self.TLS_record(TLS_HANDSHAKE, client_key_exchange)

		self.master_secret = PRF(to_bytes(self.premaster_secret), "master secret", self.client_random + self.server_random, 48)

		keys = PRF(self.master_secret, "key expansion", self.server_random + self.client_random, 20 + 20 + 32 + 32)
		self.client_write_MAC_key = keys[0:20]
		self.server_write_MAC_key = keys[20:40]
		self.client_write_key = keys[40:56]
		self.server_write_key = keys[56:72]
		self.client_write_IV = keys[72:88]
		self.server_write_IV = keys[88:102]

	def send_client_change_cipher_suite(self):
		self.client_change_cipher_spec_msg = self.TLS_record(TLS_CHANGE_CIPHER_SPEC, '01'.decode('hex'))

	def send_client_encrypted_handshake(self):
		handshake = ''.join(self.handshake_messages)
		h = SHA256.new()
		h.update(handshake)

		client_handshake_hash_computed = '\x14\x00\x00\x0c' + PRF(self.master_secret, "client finished", h.digest(), 12)
		self.handshake_messages.append(client_handshake_hash_computed)

		client_encrypted_handshake = self.client_write_IV + \
										 encrypt(client_handshake_hash_computed, self.client_write_IV, self.client_write_key, self.client_write_MAC_key, 0, TLS_HANDSHAKE)
		client_encrypted_handshake_msg = self.TLS_record(TLS_HANDSHAKE, client_encrypted_handshake)

		self.sock.sendall(self.client_key_exchange_msg + self.client_change_cipher_spec_msg)
		self.sock.sendall(client_encrypted_handshake_msg)

	# Server Change Cipher Spec and Server Encrypted Handhsake message
	# (ignored right now)
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
		ciphertext = self.client_write_IV + encrypt(plaintext, self.client_write_IV, self.client_write_key, self.client_write_MAC_key, seq_num=1, content_type=TLS_APPLICATION_DATA)

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
				plaintext = decrypt(app_data[idx+5:idx+5+size], self.server_write_key, self.server_write_MAC_key, 2, 23)

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

#############

nb_args = len(sys.argv)

if nb_args <= 1:
	print('%s <hostname> [port]' % sys.argv[0])
elif nb_args == 2:
	TLS(sys.argv[1], 443)
else:
	TLS(sys.argv[1], int(sys.argv[2]))
