#include <idniks-elgamal.hpp>

using namespace std;
using namespace mcl::bn256;

namespace IDNIKS
{
    KGC::KGC(bool set)
    {
        if (set)
        {
            setup();
        }
        else
        {
            this->set = false;
            this->params = KGCParams();
            this->masterKey = KGCMasterKey();
        }
    }

    void KGC::setup()
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

    UserKey KGC::genUserKey(const std::string &id) const // 秘密鍵の作成
    {
        if (!set)
            throw std::runtime_error("IDNIKS::KGC::genUserKey: KGC not setup");

        G1 P = this->params.P;
        Fr l = this->masterKey.l;
        G1 Pu;

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
        G1::mul(Pu, P, id_fp);
        G1 Ku;
        G1::mul(Ku, Pu, l);

        return {Ku};
    }
}
