import os
from functools import reduce

from Crypto.Hash import *
from Crypto.Cipher import AES
from Crypto.Util import Counter

from Common import *

############################
## Cipher Block Control Mode
############################

class AES_CBC:
	def __init__(self, keys, key_size, hash):

		key_size //= 8
		hash_size = hash.digest_size

		self.client_AES_key = keys[2*hash_size:2*hash_size+key_size]
		self.client_MAC_key = keys[0:hash_size]
		self.server_AES_key = keys[2*hash_size+key_size:2*hash_size+2*key_size]
		self.server_MAC_key = keys[hash_size:2*hash_size]
		self.hash = hash


	def decrypt(self, ciphertext, seq_num, content_type, debug=False):
		iv = ciphertext[0:16]
		cipher = AES.new(self.server_AES_key, AES.MODE_CBC, iv)
		decoded = cipher.decrypt(ciphertext[16:])

		padding = bytes_to_int(decoded[-1:]) + 1
		plaintext = decoded[0 : -padding-self.hash.digest_size]
		mac_decrypted = decoded[-padding-self.hash.digest_size : -padding]

		hmac = HMAC.new(self.server_MAC_key, digestmod=self.hash)
		plaintext_to_mac = nb_to_n_bytes(seq_num, 8) + nb_to_n_bytes(content_type, 1) + TLS_VERSION + nb_to_n_bytes(len(plaintext), 2) + plaintext
		hmac.update(plaintext_to_mac)
		mac_computed = hmac.digest()

		if debug:
			print('Plaintext: [' + plaintext + ']')
			print('MAC (from server): ' + bytes_to_hex(mac_decrypted))
			print('MAC (from client):  ' + bytes_to_hex(mac_computed))
			print('')

		return plaintext


	def encrypt(self, plaintext, seq_num, content_type):
		iv = os.urandom(16)
		hmac = HMAC.new(self.client_MAC_key, digestmod=self.hash)
		plaintext_to_mac = nb_to_n_bytes(seq_num, 8) + nb_to_n_bytes(content_type, 1) + TLS_VERSION + nb_to_n_bytes(len(plaintext), 2) + plaintext
		hmac.update(plaintext_to_mac)
		mac_computed = hmac.digest()

		cipher = AES.new(self.client_AES_key, AES.MODE_CBC, iv)
		plaintext += mac_computed
		padding_length = 16 - (len(plaintext) % 16)
		if padding_length == 0:
			padding_length = 16

		padding = str_to_bytes(chr(padding_length - 1)) * padding_length
	#    print(bytes_to_hex())
		ciphertext = cipher.encrypt(plaintext + padding)

		return iv + ciphertext


#######################
### Galois Counter Mode
#######################

class AES_GCM:
	def __init__(self, keys, key_size, hash):
		key_size //= 8
		
		hash_size = hash.digest_size

		self.client_AES_key = keys[0 : key_size]
		self.server_AES_key = keys[key_size : 2*key_size]
		self.client_IV = keys[2*key_size : 2*key_size+4]
		self.server_IV = keys[2*key_size+4 : 2*key_size+8]

		self.H_client = bytes_to_int(AES.new(self.client_AES_key, AES.MODE_ECB).encrypt('\x00'*16))
		self.H_server = bytes_to_int(AES.new(self.server_AES_key, AES.MODE_ECB).encrypt('\x00'*16))

	def GF_mult(self, x, y):
		product = 0
		for i in range(127, -1, -1):
			product ^= x * ((y >> i) & 1)
			x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
		return product

	def H_mult(self, H, val):
		product = 0
		for i in range(16):
			product ^= self.GF_mult(H, (val & 0xFF) << (8 * i))
			val >>= 8
		return product

	def GHASH(self, H, A, C):
		C_len = len(C)
		A_padded = bytes_to_int(A + b'\x00' * (16 - len(A) % 16))
		if C_len % 16 != 0:
			C += b'\x00' * (16 - C_len % 16)

		tag = self.H_mult(H, A_padded)

		for i in range(0, len(C) // 16):
			tag ^= bytes_to_int(C[i*16:i*16+16])
			tag = self.H_mult(H, tag)

		tag ^= bytes_to_int(nb_to_n_bytes(8*len(A), 8) + nb_to_n_bytes(8*C_len, 8))
		tag = self.H_mult(H, tag)

		return tag


	def decrypt(self, ciphertext, seq_num, content_type, debug=False):
		iv = self.server_IV + ciphertext[0:8]

		counter = Counter.new(nbits=32, prefix=iv, initial_value=2, allow_wraparound=False)
		cipher = AES.new(self.server_AES_key, AES.MODE_CTR, counter=counter)
		plaintext = cipher.decrypt(ciphertext[8:-16])

		# Computing the tag is actually pretty time consuming
		if debug:
			auth_data = nb_to_n_bytes(seq_num, 8) + nb_to_n_bytes(content_type, 1) + TLS_VERSION + nb_to_n_bytes(len(ciphertext)-8-16, 2)
			auth_tag = self.GHASH(self.H_server, auth_data, ciphertext[8:-16])
			auth_tag ^= bytes_to_int(AES.new(self.server_AES_key, AES.MODE_ECB).encrypt(iv + '\x00'*3 + '\x01'))
			auth_tag = nb_to_bytes(auth_tag)

			print('Auth tag (from server): ' + bytes_to_hex(ciphertext[-16:]))
			print('Auth tag (from client): ' + bytes_to_hex(auth_tag))

		return plaintext

	def encrypt(self, plaintext, seq_num, content_type):
		iv = self.client_IV + os.urandom(8)

		# Encrypts the plaintext
		plaintext_size = len(plaintext)
		counter = Counter.new(nbits=32, prefix=iv, initial_value=2, allow_wraparound=False)
		cipher = AES.new(self.client_AES_key, AES.MODE_CTR, counter=counter)
		ciphertext = cipher.encrypt(plaintext)

		# Compute the Authentication Tag
		auth_data = nb_to_n_bytes(seq_num, 8) + nb_to_n_bytes(content_type, 1) + TLS_VERSION + nb_to_n_bytes(plaintext_size, 2)
		auth_tag = self.GHASH(self.H_client, auth_data, ciphertext)
		auth_tag ^= bytes_to_int(AES.new(self.client_AES_key, AES.MODE_ECB).encrypt(iv + b'\x00'*3 + b'\x01'))
		auth_tag = nb_to_bytes(auth_tag)

#		print('Auth key: ' + bytes_to_hex(nb_to_bytes(self.H)))
#		print('IV:         ' + bytes_to_hex(iv))
#		print('Key:        ' + bytes_to_hex(self.client_AES_key))
#		print('Plaintext:  ' + bytes_to_hex(plaintext))
#		print('Ciphertext: ' + bytes_to_hex(ciphertext))
#		print('Auth tag:   ' + bytes_to_hex(auth_tag))

		return iv[4:] + ciphertext + auth_tag
