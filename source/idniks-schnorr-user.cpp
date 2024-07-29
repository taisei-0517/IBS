#include <idniks-schnorr.hpp>

using namespace mcl::bn256;

namespace IDNIKS
{
    User::User()
    {
        this->belong = false;
        this->id = "";
        this->decKey = UserKey();
    }

    User::User(const std::string id, const KGCParams params)
    {
        this->belong = false;
        this->id = id;
        this->params = params;
        this->decKey = UserKey();
    }

    User::User(const std::string id, const KGCParams params, const UserKey decKey)
    {
        this->belong = true;
        this->id = id;
        this->params = params;
        this->decKey = decKey;
    }

    Signature User::signature(const std::vector<unsigned char> &msg) const
    {
        if (!belong)
            throw std::runtime_error("IDNIKS::User::signature: user don't have key");

        std::vector<unsigned char> id_hash(SHA256_DIGEST_LENGTH, 0);
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, this->id.data(), this->id.size());
        SHA256_Final(id_hash.data(), &sha256);
        mpz_class id_mpz;
        mpzUtil::bytesToMpz(id_mpz, id_hash);
        mpz_class mod(Fr::getModulo());
        id_mpz %= mod;
        Fr id_fp(id_mpz.get_str());
        G1 Pu;
        G1::mul(Pu, params.P, id_fp);

        mpz_class rndk;
        mpz_class modFr(Fr::getModulo());
        mpzUtil::mpzRandDevice(rndk, modFr);
        Fr k_fp(rndk.get_str());

        Fp12 r;
        G2 QK;
        G2::mul(QK, this->params.Q, k_fp);
        pairing(r, Pu, QK);

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

        G1 eKu;
        G1::mul(eKu, this->decKey.Ku, e);
        G1 kPu;
        G1::mul(kPu, Pu, k_fp);
        G1 S;
        G1::add(S, eKu, kPu);

        return {S, e};
    }
    bool User::verification(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, Signature &sign)
    {
        Fp12 SQ_fp12;
        pairing(SQ_fp12, sign.S, params.Q);
        std::vector<unsigned char> id_hash(SHA256_DIGEST_LENGTH, 0);
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, id.data(), id.size());
        SHA256_Final(id_hash.data(), &sha256);
        mpz_class id_mpz;
        mpzUtil::bytesToMpz(id_mpz, id_hash);
        mpz_class mod(Fr::getModulo());
        id_mpz %= mod;
        Fr id_fp(id_mpz.get_str());
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

        if (sign.e == verify_e)
        {
            return 0;
        }
        else
        {
            return 1;
        }
    }
}
