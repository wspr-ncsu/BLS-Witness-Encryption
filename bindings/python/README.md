# Python bindings

Python bindings for the witenc library.

**Requirements**
Requires Python 3.8+

**Installing Witencpy and Dependencies**
You will need Public key and signature implementations from the ```blspy``` library. Run ```pip install blspy```. This library has not yet been pushed to PyPI, so you should install it using the command ```python setup.py install```. If you face deprecation errors due to the installation method, use Python 3.8 specifically. We will be updating this soon.

**Basic Usage**
```python

import time
import secrets

from blspy import (BasicSchemeMPL, G1Element, G2Element, PrivateKey)
from witencpy import (Scheme, CipherText)

# Generate private and public keys
sk: PrivateKey = BasicSchemeMPL.key_gen(secrets.token_bytes(32))
pk: G1Element = sk.get_g1()

# Generate arbitrary tag and the witness (signature on the tag)
tag: bytes = secrets.token_bytes(32)
sig: G2Element = BasicSchemeMPL.sign(sk, tag)

# Encrypting the message requires the public key and the tag
msg = b"Hello World!"
ct: CipherText = Scheme.encrypt(bytes(pk), tag, msg)

# Decrypting the ciphertext requires a witness (signature on tag)
dec: bytes = bytes(Scheme.decrypt(bytes(sig), CT))

# Ciphertext can be converted to and from bytes
ct1: CipherText = Scheme.encrypt(bytes(pk), tag, msg)
ciphertext_bytes = bytes(ct1)
ct2: Ciphertext = CipherText.from_bytes(ciphertext_bytes)
ct1 == ct2 // true
```
