import binascii
from Crypto.Hash import *

# TLS 1.2
TLS_VERSION             = '\x03\x03'

sha256WithRSAEncryption = '\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B'
sha384WithRSAEncryption = '\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0C'
sha1WithRSAEncryption = '\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05'


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
