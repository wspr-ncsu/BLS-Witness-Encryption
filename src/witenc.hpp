#ifndef SRC_BLSWITENC_HPP_
#define SRC_BLSWITENC_HPP_

#include "bls.hpp"

using std::string;

using namespace bls;

typedef G1Element G1;
typedef G2Element G2;
typedef GTElement GT;
typedef vector<uint8_t> bytes;

namespace witenc {
    class CipherText;
    class WitEnc;
    class Helpers;
    class OTP;

    class CipherText {
        public:
            G1 c1;
            bytes c2;
            bytes c3;

            CipherText();
            
            string ToHexStr() const;
            void Validate() const; // throws exception if invalid
            bytes Serialize() const;
            static CipherText Deserialize(bytes& bytes);
            static CipherText FromHexStr(const string& str);
            friend bool operator==(CipherText const &a, CipherText const &b);
    };

    class OTP {
        public:
            static bytes Exec(const bytes& key, const bytes& msg);
            static bytes Encrypt(const bytes& key, const bytes& msg);
            static bytes Decrypt(const bytes& key, const bytes& msg);
    };

    class WitEnc {
        public:
            static bytes EncodeMessage(const bytes& msg, const bytes& hash);
            static bytes DecodeMessage(const bytes& c3, const bytes& hash);
            
            static blst_scalar RandomScalar();
            static GT RandomGT();

            static CipherText Encrypt(const G1& pk, const bytes& tag, const bytes& msg);
            static blst_scalar BuildC1(CipherText& ct);
            static GT BuildC2(CipherText& ct, const G1& pk, const blst_scalar r1, const bytes& tag);
            static void BuildC3(CipherText& ct, const GT& r2, const bytes& msg);

            static bytes Decrypt(const G2& sig, const CipherText& ctxt);
            static bytes HashGT(const GT& gt);
            static GT RetrieveGT(const CipherText& ct, const G2& sig);
    };

    class Helpers {
        public:
            static void RemoveTrailingZeroes(bytes &bytes);
    };
} 

#endif