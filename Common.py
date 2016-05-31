import binascii

from Crypto.Hash import *

# TLS 1.2
TLS_VERSION             = b'\x03\x03'

sha256WithRSAEncryption = b'\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B'
sha384WithRSAEncryption = b'\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0C'
sha1WithRSAEncryption = b'\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05'


def bytes_to_int(s):
    # In Python 3 one might receive an int
    if type(s) == int:
        return s
    return int(binascii.hexlify(s), 16)

def bytes_to_hex(s):
    return bytes_to_str(binascii.hexlify(s))

def nb_to_bytes(n):
    h = '%x' % n
    s = binascii.unhexlify('0'*(len(h) % 2) + h)
    return s

def nb_to_n_bytes(number, size):
	h = '%x' % number
	s = binascii.unhexlify('0'*(size*2 - len(h)) + h)
	return s

def hex_to_bytes(s):
    return binascii.unhexlify(s)

def str_to_bytes(s):
    try:
        # Python 3
        return bytes(s, 'utf-8')
    except:
        # Python 2
        return s

def bytes_to_str(b):
    try:
        # Python 3
        return str(b, 'utf-8')
    except:
        # Python 2
        return b
