#include <idniks-schnorr.hpp>

using namespace IDNIKS;

int main()
{
    initPairing();

    KGC kgc;
    kgc.setup();
    printf("setup完了\n");

    KGCParams params = kgc.getParams();
    std::cout << "P: " << params.P << std::endl;
    std::cout << "Q: " << params.Q << std::endl;
    std::cout << "lQ: " << params.lQ << std::endl;

    std::string userId = "uki.uki.taisei@ezweb.ne.jp";
    UserKey userKey = kgc.genUserKey(userId);

    User user(userId, params, userKey);

    std::string str = "Hello, World!";
    std::vector<unsigned char> message(str.begin(), str.end());
    std::cout << "message: " << message[0] << std::endl;
    Signature sign = user.signature(message);
    std::string userId_fake = "user2";

    // bool valid = user.verification(message, userId_fake, params, sign);
    bool valid = user.verification(message, userId, params, sign);

    if (valid)
    {
        printf("Signature is valid.\n");
    }
    else
    {
        printf("Signature is invalid.\n");
    }

    return 0;
}