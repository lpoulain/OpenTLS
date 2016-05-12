# A simple HTTPS client in Python

This is a simple HTTPS client implementing TLS 1.2. It supports right now the following cipher suites:

- TLS\_ECDHE\_RSA\_WITH\_AES\_128\_CBC\_SHA (secp256r1 and secp384r1 elliptic curves)
- TLS\_DHE\_RSA\_WITH\_AES\_128\_CBC\_SHA
- TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA

**WARNING**: as most, this code should NOT be considered secured. Its use is mostly educational (if you want to learn about how TLS works) and/or if you want to access Website which only support HTTPS.

### Requirements

- Python 2.7
- [Pycrypto](https://www.dlitz.net/software/pycrypto/)
- [TinyEC](https://pypi.python.org/pypi/tinyec)
