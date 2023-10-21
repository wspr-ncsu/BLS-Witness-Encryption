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

void test_encoding_and_decoding_msg_and_hash() {
    vector<uint8_t> msg = getRandomSeed(); // "Hello" in ASCII
    vector<uint8_t> hash = getRandomSeed(); // "world" in ASCII

    vector<uint8_t> c3 = Scheme::MaskMessage(msg, hash);
    vector<uint8_t> decoded = Scheme::UnmaskMessage(c3, hash);
    
    ASSERT(msg == decoded);
}

void test_ciphertext_serialization()
{
    CipherText ct = randomCtx();
    vector<uint8_t> serilized = ct.Serialize();
    CipherText ct2 = CipherText::Deserialize(serilized);
    ct2.Validate();
    ASSERT( ct == ct2 );
    ASSERT( ct.ToHexStr() == ct2.ToHexStr() );
    CipherText cxt = CipherText::FromHexStr(ct.ToHexStr());
    ASSERT( ct == cxt && ct2 == cxt );
}

void test_encryption_scheme_is_correct() 
{
    vector<uint8_t> msg = vector<uint8_t> {104, 101, 108, 108, 111}; // "Hello" in ASCII
    vector<uint8_t> tag = vector<uint8_t> {119, 111, 114, 108, 100}; // "world" in ASCII

    PrivateKey sk = BasicSchemeMPL().KeyGen(getRandomSeed());
    G1Element pk = sk.GetG1Element();

    CipherText ctxt = Scheme::Encrypt(pk, tag, msg);

    G2Element sig = BasicSchemeMPL().Sign(sk, tag);
    vector<uint8_t> msg2 = Scheme::Decrypt(sig, ctxt);

    ASSERT(msg == msg2);
}

void test_GT_division_operator()
{
    GTElement gt1 = Helpers::RandomGT();
    GTElement gt2 = Helpers::RandomGT();
    GTElement prod = gt1 * gt2;

    ASSERT( gt1 == (prod / gt2) && gt2 == (prod / gt1) );
}

void test_pairing_correctness()
{
    vector<uint8_t> msg = vector<uint8_t> {104, 101, 108, 108, 111}; // "Hello" in ASCII
    vector<uint8_t> tag = vector<uint8_t> {119, 111, 114, 108, 100}; // "world" in ASCII

    PrivateKey sk = BasicSchemeMPL().KeyGen(getRandomSeed());
    G1Element pk = sk.GetG1Element();
    G2Element sig = BasicSchemeMPL().Sign(sk, tag);

    CipherText ct;

    blst_scalar r1 = Scheme::BuildC1(ct);

    G2Element g2_map = G2Element::FromMessage(tag,
            (const uint8_t*)BasicSchemeMPL::CIPHERSUITE_ID.c_str(),
            BasicSchemeMPL::CIPHERSUITE_ID.length());

    ASSERT(pk.Pair(r1 * g2_map) == g2_map.Pair(r1 * pk)) // bi-linear property

    ASSERT(pk.Pair(r1 * g2_map) == ct.c1.Pair(sig) ) // bi-linear property
}

void test_primitive_steps()
{
    //message and tag
    vector<uint8_t> msg = vector<uint8_t> {104, 101, 108, 108, 111}; // "Hello" in ASCII
    vector<uint8_t> tag = vector<uint8_t> {119, 111, 114, 108, 100}; // "world" in ASCII

    // Generate private keys, public keys and signature on tag
    PrivateKey sk = BasicSchemeMPL().KeyGen(getRandomSeed());
    G1Element pk = sk.GetG1Element();
    G2Element sig = BasicSchemeMPL().Sign(sk, tag);

    CipherText ct;

    // Generate r1 and c1
    blst_scalar r1 = Scheme::BuildC1(ct);
    
    GTElement r2 = Helpers::RandomGT();
    G2Element g2_map = G2Element::FromMessage(tag,
            (const uint8_t*)BasicSchemeMPL::CIPHERSUITE_ID.c_str(),
            BasicSchemeMPL::CIPHERSUITE_ID.length());

    ASSERT(pk.Pair(r1 * g2_map) == g2_map.Pair(r1 * pk)) // bi-linear property

    ASSERT(pk.Pair(r1 * g2_map) == ct.c1.Pair(sig) ) // bi-linear property

    GTElement pair = pk.Pair(r1 * g2_map);
    GTElement c2 = pair * r2;

    ASSERT( c2 == r2 * pair) // commutative property
    ASSERT( pair == c2 / r2 ) // can we get back pair from c2 and r2?
    ASSERT( r2 == c2 / pair ) // can we get back r2 from c2 and pair?

    ct.c2 = c2.Serialize();
    GTElement imported_c2 = GTElement::FromByteVector(ct.c2);
    ASSERT( c2 == imported_c2 )

    ASSERT( imported_c2 == r2 * pair) // commutative property
    ASSERT( pair == imported_c2 / r2 ) // can we get back pair from imported_c2 and r2?
    ASSERT( r2 == imported_c2 / pair ) // can we get back r2 from imported_c2 and pair?

    ASSERT( ct.c2 == imported_c2.Serialize() )

    vector<uint8_t> hash_r2 = Scheme::HashGT(r2);
    ct.c3 = Scheme::MaskMessage(msg, hash_r2);

    string ct_str = ct.ToHexStr();
    CipherText imported_ct = CipherText::FromHexStr(ct_str);

    ASSERT( ct == imported_ct )
    // ASSERT( r2 == Scheme::RetrieveGT(imported_ct, sig) )

    GTElement new_c2 = GTElement::FromByteVector(imported_ct.c2);

    ASSERT( new_c2 == c2 );
    ASSERT(imported_ct.c1.Pair(sig) == sig.Pair(imported_ct.c1)) // bi-linear property

    ASSERT(pk.Pair(r1 * g2_map) == imported_ct.c1.Pair(sig) ) // bi-linear property
    
    GTElement new_pair = imported_ct.c1.Pair(sig);

    ASSERT( new_pair == pair );

    GTElement new_r2 = new_c2 / new_pair;

    ASSERT( new_r2 == r2 );

    vector<uint8_t> new_hash_r2 = Scheme::HashGT(new_r2);

    vector<uint8_t> new_msg = Scheme::UnmaskMessage(imported_ct.c3, new_hash_r2);

    ASSERT( new_msg == msg );
}

void test_xor_class()
{
    vector<uint8_t> key = getRandomSeed();
    vector<uint8_t> msg = getRandomSeed();

    vector<uint8_t> ct = OTP::Encrypt(key, msg);
    vector<uint8_t> msg2 = OTP::Decrypt(key, ct);

    ASSERT( msg2 == msg );
}

int main(int argc, char* argv[])
{
    test_xor_class();
    test_encoding_and_decoding_msg_and_hash();
    test_ciphertext_serialization();
    test_encryption_scheme_is_correct();
    test_primitive_steps();
    test_GT_division_operator();
    test_pairing_correctness();

    return 0;
}