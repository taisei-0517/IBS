#ifndef _INC_IDNIKS
#define _INC_IDNIKS

#include <mcl/bn256.hpp>
#include <openssl/sha.h>

using namespace mcl::bn256;

namespace IDNIKS{
  struct KGCParams{
    G1 P;
    G2 Q;
    G2 lQ;

    KGCParams() = default;
    //KGCParams(const G1 P, const G2 Q, const G2 lQ);

    bool operator==(const KGCParams &params) const;
  };

  struct KGCMasterKey{
    Fr l;

    KGCMasterKey() = default;
    //KGCMasterKey(const Fr l);
  };

  struct UserKey{
    G1 Ku;

    UserKey() = default;
    UserKey(const G1 Ku);
  };

  /*struct Cipher{
    G2 C1;
    std::vector<unsigned char> C2;

    Cipher() = default;
    Cipher(const G2 C1, const std::vector<unsigned char> C2);
  };*/

  struct Signature{
    G1 S;
    G2 R;

    Signature() = default;
    Signature(const G1 S, const G2 R);
  };

  class KGC{
    private:
      KGCParams params;
      KGCMasterKey masterKey;
      bool set;

    public:
      KGC(bool set=true);
      //KGC(const KGCParams params, const KGCMasterKey masterKey);
      void setup(); //1
      UserKey genUserKey(const std::string &id) const; //2
      void setParams(KGCParams params){ this->params = params; };
      void setMasterKey(KGCMasterKey masterKey){ this->masterKey = masterKey; };
      KGCParams getParams() const{ return params; };
      KGCMasterKey getMasterKey() const{ return masterKey; };
      bool isSet() const{ return set; }
  };

  class User{
    private:
      std::string id;
      KGCParams params;
      UserKey decKey;
      bool belong;
    public:
      User();
      User(const std::string id, const KGCParams params);
      User(const std::string id, const KGCParams params, const UserKey decKey);
      //void belongKGC(const std::string id, const KGCParams params, const UserKey decKey);
      Signature signature(const std::vector<unsigned char> &msg) const; //3
      static bool verification(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, Signature &sign); //4
      //std::string getId() const{ return id; };
      //UserKey getUserKey() const{ return decKey; };
      //bool isBelong() const{ return belong; };
  };

  //void initIDNIKS();

  //void canonical(std::vector<unsigned char>& s, const Fp12 &v, int o=0);

  //void hashToRange(mpz_class& v, const std::vector<unsigned char> &s, const mpz_class &n);
}

#endif
