# Witness Encryption implementation based on BLS Signatures 

Implements Witness Encryption based on BLS signatures using BLS Signatures implementation from [Chia-Network/bls-signatures](https://github.com/Chia-Network/bls-signatures)
for cryptographic primitives (pairings, EC, hashing).

## Features:

* Encryption using public verification key, message and a message tag
* Decryption using the ciphertext and a valid signature on the message tag
* [Python bindings](https://github.com/kofi-dalvik/bls-witness-encryption/tree/main/bindings/python)

## Before you start

If you're using ```C/C++``` then [Chia-Network/bls-signatures](https://github.com/Chia-Network/bls-signatures) is available within this library to use. 
If you prefer to use the python bidnings, then you need to install ```blspy``` as this library is based on BLS signatures so refer to [Chia-Network/bls-signatures](https://github.com/Chia-Network/bls-signatures) for details on generating public and private key pairs. 

Refer to [Python bindings](https://github.com/kofi-dalvik/bls-witness-encryption/tree/main/bindings/python/README.md) for instructions.

## Import the library

```c++
#include "witenc.hpp"
using namespace bls;
using namespace witenc;
```

## Creating keys and signatures

```c++
// Example seed, used to generate private key. Always use
// a secure RNG with sufficient entropy to generate a seed (at least 32 bytes).
vector<uint8_t> seed = {0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                        19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                        12, 62, 89, 110, 182, 9,   44, 20,  254, 22};

PrivateKey sk = BasicSchemeMPL().KeyGen(seed);
G1Element pk = sk.GetG1Element();

vector<uint8_t> message = {1, 2, 3, 4, 5};  // Message is passed in as a byte vector
G2Element signature = BasicSchemeMPL().Sign(sk, message);

// Verify the signature
bool ok = BasicSchemeMPL().Verify(pk, message, signature);
```

## Serializing keys and signatures to bytes

```c++
vector<uint8_t> skBytes = sk.Serialize();
vector<uint8_t> pkBytes = pk.Serialize();
vector<uint8_t> signatureBytes = signature.Serialize();

cout << Util::HexStr(skBytes) << endl;    // 32 bytes printed in hex
cout << Util::HexStr(pkBytes) << endl;    // 48 bytes printed in hex
cout << Util::HexStr(signatureBytes) << endl;  // 96 bytes printed in hex
```

## Loading keys and signatures from bytes

```c++
// Takes vector of 32 bytes
PrivateKey skc = PrivateKey::FromByteVector(skBytes);

// Takes vector of 48 bytes
G1Element pk = G1Element::FromByteVector(pkBytes);

// Takes vector of 96 bytes
G2Element signature = G2Element::FromByteVector(signatureBytes);
```


## Encrypting message with tag
```c++
G1Element pk;  // This should be a valid public key
vector<uint8_t> msg = vector<uint8_t> {104, 101, 108, 108, 111}; // arbitrary length
vector<uint8_t> tag = vector<uint8_t> {119, 111, 114, 108, 100};  // arbitrary length

CipherText ctxt = Scheme::Encrypt(pk, tag, msg);
```

## Serializing/loading Ciphertext to/from bytes
```c++
CipherText ct; // This should be a valid ciphertext
vector<uint8_t> serilized = ct.Serialize();
CipherText ct2 = CipherText::Deserialize(serilized);
```

## Decrypting message with signed tag
```c++
CipherText ctxt; // Valid CipherText from encryption
G2Element signature; // valid signature created from signing the tag used in encryption
vector<uint8_t> msg = Scheme::Decrypt(sig, ctxt);
```

## Build

Cmake 3.14+, a c++ compiler, and python3.8 (for bindings) are required for building.

```bash
mkdir build
cd build
cmake ../
cmake --build . -- -j 6
```

### Run tests

```bash
./build/src/runtest
```

### Run benchmarks

```bash
./build/src/webench
```

## Notes on dependencies

We use Libsodium which provides secure memory
allocation. To install it, either download them from github and
follow the instructions for each repo, or use a package manager like APT or
brew.

## Discussion

Create an issue.


## Contributing

Contributions are welcome.


## BLS Signatures license

BLS signature is used with the
[Apache 2.0 license](https://github.com/Chia-Network/bls-signatures/blob/main/LICENSE)
