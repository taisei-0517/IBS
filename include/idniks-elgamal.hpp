#ifndef _ELGAMAL_IDNIKS
#define _ELGAMAL_IDNIKS

#include <mcl/bn256.hpp>
#include <openssl/sha.h>
// #include <vector>
#include <mpz_util.hpp>

using namespace mcl::bn256;

namespace IDNIKS
{
    struct KGCParams
    {
        G1 P;
        G2 Q;
        G2 lQ;

        KGCParams() = default;

        bool operator==(const KGCParams &params) const;
    };

    struct KGCMasterKey
    {
        Fr l;

        KGCMasterKey() = default;
    };

    struct UserKey
    {
        G1 Ku;

        UserKey() = default;
        UserKey(const G1 Ku);
    };

    struct Signature
    {
        G1 S;
        G2 R;

        Signature() = default;
        Signature(const G1 S, const G2 R);
    };

    class KGC
    {
    private:
        KGCParams params;
        KGCMasterKey masterKey;
        bool set;

    public:
        KGC(bool set = true);
        void setup();
        UserKey genUserKey(const std::string &id) const;
        void setParams(KGCParams params) { this->params = params; }
        void setMasterKey(KGCMasterKey masterKey) { this->masterKey = masterKey; }
        KGCParams getParams() const { return params; }
        KGCMasterKey getMasterKey() const { return masterKey; }
        bool isSet() const { return set; }
    };

    class User
    {
    private:
        std::string id;
        KGCParams params;
        UserKey decKey;
        bool belong;

    public:
        User();
        User(const std::string id, const KGCParams params);
        User(const std::string id, const KGCParams params, const UserKey decKey);
        Signature signature(const std::vector<unsigned char> &msg) const;
        static bool verification(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, Signature &sign);
    };
}

#endif 