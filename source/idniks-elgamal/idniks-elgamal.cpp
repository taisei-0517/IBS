#include <idniks-elgamal.hpp>

using namespace mcl::bn256;

namespace IDNIKS
{
    bool KGCParams::operator==(const KGCParams &params) const
    {
        return this->Q == params.Q && this->lQ == params.lQ && this->P == params.P;
    }

    UserKey::UserKey(const G1 Ku)
    {
        this->Ku = Ku;
    }
    Signature::Signature(const G1 S, const G2 R)
    {
        this->S = S;
        this->R = R;
    }
}
