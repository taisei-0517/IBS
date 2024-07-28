#ifndef _ELGAMAL_IDNIKS
#define _ELGAMAL_IDNIKS

#include <mcl/bn256.hpp>
#include <openssl/sha.h>
#include <vector>
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

        bool operator==(const KGCParams &params) const
        {
            return (P == params.P && Q == params.Q && lQ == params.lQ);
        }
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
        UserKey(const G1 Ku) : Ku(Ku) {}
    };

    struct Signature
    {
        G1 S;
        G2 R;

        Signature() = default;
        Signature(const G1 S, const G2 R) : S(S), R(R) {}
    };

    class KGC
    {
    private:
        KGCParams params;
        KGCMasterKey masterKey;
        bool set;

    public:
        KGC(bool set = true) : set(set) {}
        void setup()
        {
            this->set = true;

            G1 P;
            mpz_class rndP_mpz;
            mpz_class modG1(G1::BaseFp::getModulo());
            mpzUtil::mpzRandDevice(rndP_mpz, modG1);
            Fp rndP(rndP_mpz.get_str());
            mapToG1(P, rndP);

            G2 Q;
            mpz_class rndQ_mpz1;
            mpz_class rndQ_mpz2;
            mpz_class modG2(G2::BaseFp::BaseFp::getModulo());
            mpzUtil::mpzRandDevice(rndQ_mpz1, modG2);
            mpzUtil::mpzRandDevice(rndQ_mpz2, modG2);
            Fp2 rndQ(rndQ_mpz1.get_str(), rndQ_mpz2.get_str());
            mapToG2(Q, rndQ);

            Fr l;
            l.setRand();

            G2 lQ;
            G2::mul(lQ, Q, l);

            this->params = {P, Q, lQ};
            this->masterKey = {l};
        }
        UserKey genUserKey(const std::string &id) const //秘密鍵の作成
        {
            if (!set)
                throw std::runtime_error("IDNIKS::KGC::genUserKey: KGC not setup");

            G1 P = this->params.P;
            Fr l = this->masterKey.l;

            // Pu : h(id)P
            G1 Pu;

            // hash(id)
            std::vector<unsigned char> id_hash(SHA256_DIGEST_LENGTH, 0);
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, id.data(), id.size());
            SHA256_Final(id_hash.data(), &sha256);

            // id: bytes to Fr
            mpz_class id_mpz;
            mpzUtil::bytesToMpz(id_mpz, id_hash);
            mpz_class mod(Fr::getModulo());
            id_mpz %= mod;
            Fr id_fp(id_mpz.get_str());

            G1::mul(Pu, P, id_fp);

            // Ku : lPu
            // l : MasterSecretKey
            G1 Ku;
            G1::mul(Ku, Pu, l);

            return {Ku};
        }
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
        User() : belong(false) {}
        User(const std::string id, const KGCParams params) : id(id), params(params), belong(false) {}
        User(const std::string id, const KGCParams params, const UserKey decKey) : id(id), params(params), decKey(decKey), belong(true) {}
        Signature signature(const std::vector<unsigned char> &msg) const
        {
            if (!belong)
                throw std::runtime_error("IDNIKS::User::signature: user don't have key");

            // hash(id)
            std::vector<unsigned char> id_hash(SHA256_DIGEST_LENGTH, 0);
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, this->id.data(), this->id.size());
            SHA256_Final(id_hash.data(), &sha256);
            // id: bytes to Fr
            mpz_class id_mpz;
            mpzUtil::bytesToMpz(id_mpz, id_hash);
            mpz_class mod(Fr::getModulo());
            id_mpz %= mod;
            Fr id_fp(id_mpz.get_str());
            // Pu : h(id)P
            G1 Pu;
            G1::mul(Pu, params.P, id_fp);

            // choice k random
            mpz_class rndk;
            mpz_class modFr(Fr::getModulo());
            mpzUtil::mpzRandDevice(rndk, modFr);
            Fr k(rndk.get_str());

            // R = k*Q
            G2 R;
            G2::mul(R, this->params.Q, k);

            // hash(msg)
            std::vector<unsigned char> msg_hash(SHA256_DIGEST_LENGTH, 0);
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, msg.data(), msg.size());
            SHA256_Final(msg_hash.data(), &sha256);
            // msg: bytes to Fr
            mpz_class msg_mpz;
            mpzUtil::bytesToMpz(msg_mpz, msg_hash);
            msg_mpz %= mod;
            Fr msg_fr(msg_mpz.get_str());
            // h(m)/k
            Fr a;
            Fr::div(a, msg_fr, k);
            // a*Pu
            G1 aPu;
            G1::mul(aPu, Pu, a);

            // R.x/k
            Fr x(R.x.getStr());
            Fr b;
            Fr::div(b, x, k);
            // b*Ku
            G1 bKu;
            G1::mul(bKu, this->decKey.Ku, b);

            // S = aPu + bKu
            G1 S;
            G1::add(S, aPu, bKu);

            return {S, R};
        }
        bool verification(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, Signature &sign)
        {
            // verification
            // e(S, R) == e(Pu, Q)^h(m) * e(Pu, lQ)^x
            // x = R.x
            // sign_fp12 == verify_fp12
            // verify_fp12 = verify_fp12_a * verify_fp12_b

            // hash(id)
            std::vector<unsigned char> id_hash(SHA256_DIGEST_LENGTH, 0);
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, id.data(), id.size());
            SHA256_Final(id_hash.data(), &sha256);
            // id: bytes to Fr
            mpz_class id_mpz;
            mpzUtil::bytesToMpz(id_mpz, id_hash);
            mpz_class mod(Fr::getModulo());
            id_mpz %= mod;
            Fr id_fp(id_mpz.get_str());
            // Pu : h(id)P
            G1 Pu;
            G1::mul(Pu, params.P, id_fp);

            // e(S, R)
            Fp12 sign_fp12;
            pairing(sign_fp12, sign.S, sign.R);

            // e(Pu, Q)^h(msg) * e(Pu, lQ)^x
            // verify_fp12_a * verify_fp12_b = verify_fp12
            Fp12 verify_fp12;
            Fp12 verify_fp12_a;
            Fp12 verify_fp12_b;

            // verify_fp12_a = e(Pu, Q)^h(msg)
            //               = e(Pu, h(msg)*Q)
            // hash(msg)
            std::vector<unsigned char> msg_hash(SHA256_DIGEST_LENGTH, 0);
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, msg.data(), msg.size());
            SHA256_Final(msg_hash.data(), &sha256);
            // msg: bytes to Fr
            mpz_class msg_mpz;
            mpzUtil::bytesToMpz(msg_mpz, msg_hash);
            msg_mpz %= mod;
            Fr msg_fr(msg_mpz.get_str());
            // hQ : h(msg)Q
            G2 hQ;
            G2::mul(hQ, params.Q, msg_fr);
            // pairing (Pu, Q^h(msg))
            pairing(verify_fp12_a, Pu, hQ);

            // verify_fp12_b = e(Pu, lQ)^x
            //               = e(Pu, x*lQ)
            // xlQ : x*lQ
            // x = R.x
            Fr x(sign.R.x.getStr());
            G2 xlQ;
            G2::mul(xlQ, params.lQ, x);
            // pairing (Pu, xlQ)
            pairing(verify_fp12_b, Pu, xlQ);

            // verify_fp12 = verify_fp12_a * verify_fp12_b
            Fp12::mul(verify_fp12, verify_fp12_a, verify_fp12_b);

            // if(e(S, R) == e(Pu, Q)^h(m) * e(Pu, lQ)^x) ? true : false
            // std::cout << "sign_fp12: " << sign_fp12;
            // std::cout << "\nverify_fp12: " << verify_fp12;

            if (sign_fp12 == verify_fp12)
            {
                return 0;
            }else{
                return 1;
            }
        }
    };
}

#endif