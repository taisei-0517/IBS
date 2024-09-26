#include <idniks-elgamal.hpp>

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
        Fr k(rndk.get_str());

        G2 R;
        G2::mul(R, this->params.Q, k);
        std::vector<unsigned char> msg_hash(SHA256_DIGEST_LENGTH, 0);
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, msg.data(), msg.size());
        SHA256_Final(msg_hash.data(), &sha256);
        mpz_class msg_mpz;
        mpzUtil::bytesToMpz(msg_mpz, msg_hash);
        msg_mpz %= mod;
        Fr msg_fr(msg_mpz.get_str());
        Fr a;
        Fr::div(a, msg_fr, k);
        G1 aPu;
        G1::mul(aPu, Pu, a);
        Fr x(R.x.getStr());
        Fr b;
        Fr::div(b, x, k);
        G1 bKu;
        G1::mul(bKu, this->decKey.Ku, b);
        G1 S;
        G1::add(S, aPu, bKu);

        return {S, R};
    }
    bool User::verification(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, Signature &sign)
    {
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
        Fp12 sign_fp12;
        pairing(sign_fp12, sign.S, sign.R);

        Fp12 verify_fp12;
        Fp12 verify_fp12_a;
        Fp12 verify_fp12_b;
        std::vector<unsigned char> msg_hash(SHA256_DIGEST_LENGTH, 0);
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, msg.data(), msg.size());
        SHA256_Final(msg_hash.data(), &sha256);
        mpz_class msg_mpz;
        mpzUtil::bytesToMpz(msg_mpz, msg_hash);
        msg_mpz %= mod;
        Fr msg_fr(msg_mpz.get_str());
        G2 hQ;
        G2::mul(hQ, params.Q, msg_fr);
        pairing(verify_fp12_a, Pu, hQ);
        Fr x(sign.R.x.getStr());
        G2 xlQ;
        G2::mul(xlQ, params.lQ, x);
        pairing(verify_fp12_b, Pu, xlQ);
        Fp12::mul(verify_fp12, verify_fp12_a, verify_fp12_b);

        if (sign_fp12 == verify_fp12)
        {
            return 0;
        }
        else
        {
            return 1;
        }
    }
};
