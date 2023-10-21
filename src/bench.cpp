#include <chrono>

#include "witenc.hpp"
#include "test-utils.hpp"

using std::string;
using std::vector;

using namespace witenc;

const int numIters = 1000;

CipherText randomCtx()
{
    CipherText ct;
    vector<uint8_t> s1 = getRandomSeed();
    vector<uint8_t> s2 = getRandomSeed();
    vector<uint8_t> s3 = getRandomSeed();

    G1Element g1 = G1Element::FromMessage(s1, s1.data(), s1.size());
    G2Element g2 = G2Element::FromMessage(s2, s2.data(), s2.size());
    G1Element g3 = G1Element::FromMessage(s2, s2.data(), s2.size());

    GTElement gt1 = g1.Pair(g2);
    GTElement gt2 = g2.Pair(g3);
    GTElement gt3 = gt1 * gt2;

    ct.c1 = g1;
    ct.c2 = gt3.Serialize();
    ct.c3 = getRandomSeed();

    ct.Validate();

    return ct;
}

void bench_ciphertexts_serialize_and_deserialize()
{
    CipherText ct = randomCtx();
    string hex;

    auto start = startStopwatch();
    for (int i = 0; i < numIters; i++) {
        hex = ct.ToHexStr();
    }
    endStopwatch("Ciphertext::ToHexStr()", start, numIters);

    start = startStopwatch();
    for (int i = 0; i < numIters; i++) {
        CipherText::FromHexStr(hex);
    }
    endStopwatch("Ciphertext::FromHexStr()", start, numIters);
}

void bench_encryption_decryptions() 
{
    vector<uint8_t> msg = getRandomSeed();
    vector<uint8_t> tag = getRandomSeed();

    // Generate private keys, public keys and signature on tag
    PrivateKey sk = BasicSchemeMPL().KeyGen(getRandomSeed());
    G1Element pk = sk.GetG1Element();

    G2Element sig = BasicSchemeMPL().Sign(sk, tag);
    CipherText ct;

    auto start = startStopwatch();
    for (int i = 0; i < numIters; i++) {
        ct = Scheme::Encrypt(pk, tag, msg);
    }
    endStopwatch("Encryption", start, numIters);

    vector<uint8_t> decrypted;

    start = startStopwatch();
    for (int i = 0; i < numIters; i++) {
        decrypted = Scheme::Decrypt(sig, ct);
    }
    endStopwatch("Decryption", start, numIters);
}

int main(int argc, char* argv[])
{
    bench_encryption_decryptions();
    bench_ciphertexts_serialize_and_deserialize();
}