# OpenTLS: a simple HTTPS client in Python

This is a simple HTTPS client implementing TLS 1.2. It supports right now the following cipher suites:

- TLS\_ECDHE\_RSA\_WITH\_AES\_128\_CBC\_SHA (secp256r1 and secp384r1 elliptic curves)
- TLS\_DHE\_RSA\_WITH\_AES\_128\_CBC\_SHA
- TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA

It is also checking the validity of the whole SSL certificate chain, down to its own list of Root Certificates (stored in root_certificates.pem)

**WARNING**: as most crypto software, this code should NOT be considered secured (it is extremely difficult to implement really secure software that uses cryptography). Its use is mostly educational (if you want to learn about how TLS works) and/or if you want to access Website which only support HTTPS.

### Requirements

- Python 2.7
- [Pycrypto](https://www.dlitz.net/software/pycrypto/)
- [TinyEC](https://pypi.python.org/pypi/tinyec)

#### Future improvements

- Python 3 support
- Better management of HTTP response
- AES 256-bit support
- Galois Counter Mode (GCM) support
- Verification of the server-sent MAC and Encrypted Handshake Message
