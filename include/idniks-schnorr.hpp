#ifndef _SCHONORR_IDNIKS
#define _SCHONORRL_IDNIKS

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
        Fr e;

        Signature() = default;
        Signature(const G1 S, const Fr e) : S(S), e(e) {}
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
            Fr k_fp(rndk.get_str());

            // r = e(Pu,Q)^k
            Fp12 r;
            G2 QK;
            G2::mul(QK, this->params.Q, k_fp);
            pairing(r, Pu, QK);

            // e = h(m||r)
            std::vector<unsigned char> k_m(r.getStr().begin(), r.getStr().end());
            std::vector<unsigned char> msg_m = msg;
            msg_m.insert(msg_m.end(), k_m.begin(), k_m.end());
            std::vector<unsigned char> e_hash(SHA256_DIGEST_LENGTH, 0);
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, msg.data(), msg_m.size());
            SHA256_Final(e_hash.data(), &sha256);
            mpz_class e_mpz;
            mpzUtil::bytesToMpz(e_mpz, e_hash);
            e_mpz %= mod;
            Fr e(e_mpz.get_str());

            // S = eKu + kPu = (el+k)Pu
            G1 eKu;
            G1::mul(eKu, this->decKey.Ku, e);
            G1 kPu;
            G1::mul(kPu, Pu, k_fp);
            G1 S;
            G1::add(S, eKu, kPu);

            return {S, e};
        }
        bool verification(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, Signature &sign)
        {
            // verification
            // w = e(S,Q) * e(Pu, lQ)^-e
            //   = e(S,Q) * e(Pu, (-e) * lQ)
            Fp12 SQ_fp12;
            pairing(SQ_fp12, sign.S, params.Q);

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
            G2 elQ;
            G2::mul(elQ, params.lQ, -sign.e);
            Fp12 ePu_fp12;
            pairing(ePu_fp12, Pu, elQ);
            Fp12 w;
            Fp12::mul(w, SQ_fp12, ePu_fp12);
            
            std::vector<unsigned char> w_s(w.getStr().begin(), w.getStr().end());
            std::vector<unsigned char> msg_s = msg;
            msg_s.insert(msg_s.end(), w_s.begin(), w_s.end());
            std::vector<unsigned char> e_hash(SHA256_DIGEST_LENGTH, 0);
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, msg.data(), msg.size());
            SHA256_Final(e_hash.data(), &sha256);
            mpz_class e_mpz;
            mpzUtil::bytesToMpz(e_mpz, e_hash);
            e_mpz %= mod;
            Fr verify_e(e_mpz.get_str());

            if(sign.e == verify_e)
            {
                return 0;
            }else{
                return 1;
            }
        }
    };
}

#endif