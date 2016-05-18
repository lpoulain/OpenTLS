# OpenTLS: a HTTPS client in Python

This is a HTTPS client implementing TLS 1.2 which supports the most popular cipher suites, including the Galois-Counter Mode (GCM):

- TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA
- TLS\_RSA\_WITH\_AES\_256\_CBC\_SHA
- TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA256
- TLS\_RSA\_WITH\_AES\_256\_CBC\_SHA256
- TLS\_RSA\_WITH\_AES\_128\_GCM\_SHA256
- TLS\_RSA\_WITH\_AES\_256\_GCM\_SHA384
- TLS\_DHE\_RSA\_WITH\_AES\_128\_CBC\_SHA
- TLS\_DHE\_RSA\_WITH\_AES\_256\_CBC\_SHA
- TLS\_DHE\_RSA\_WITH\_AES\_128\_CBC\_SHA256
- TLS\_DHE\_RSA\_WITH\_AES\_256\_CBC\_SHA256
- TLS\_DHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256
- TLS\_DHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384
- TLS\_ECDHE\_RSA\_WITH\_AES\_128\_CBC\_SHA
- TLS\_ECDHE\_RSA\_WITH\_AES\_256\_CBC\_SHA
- TLS\_ECDHE\_RSA\_WITH\_AES\_128\_CBC\_SHA256
- TLS\_ECDHE\_RSA\_WITH\_AES\_256\_CBC\_SHA256
- TLS\_ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256
- TLS\_ECDHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384

It is also checking the validity of the whole SSL certificate chain, down to its own list of Root Certificates (stored in root_certificates.pem)

**WARNING**: as most crypto software, this code should NOT be considered 100% secured (it is extremely difficult to implement really secure software that uses cryptography). Its use is mostly educational (if you want to learn about how TLS works), if you want to pentest a system and/or if you want to access Website which only support HTTPS.

### Requirements

- Python 2.7
- [Pycrypto](https://www.dlitz.net/software/pycrypto/)
- [TinyEC](https://pypi.python.org/pypi/tinyec)

#### Future improvements

- Python 3 support
- Better management of HTTP response
- Verification of the server-sent MAC and Encrypted Handshake Message
