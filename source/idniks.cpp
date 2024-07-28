// #include <mcl/bn256.hpp>
// #include <openssl/sha.h>
// #include <stdio.h>
// #include <string>
// #include <iostream>
// #include <vector>
#include <idniks_elgamal.hpp>

int main() {
    // std::cout << "たいせい" << std::endl;
    initPairing();
    using namespace IDNIKS;

    // KGCをセットアップ
    KGC kgc;
    kgc.setup();
    printf("setup完了\n");

    // KGCのパラメータを取得
    KGCParams params = kgc.getParams();
    std::cout << "P: " << params.P << std::endl;
    std::cout << "Q: " << params.Q << std::endl;
    std::cout << "lQ: " << params.lQ << std::endl;

    // ユーザーIDを指定してユーザーキーを生成
    std::string userId = "uki.uki.taisei@ezweb.ne.jp";
    UserKey userKey = kgc.genUserKey(userId);

    // ユーザーを生成
    User user(userId, params, userKey);

    // メッセージに署名
    std::string str = "Hello, World!";
    std::vector<unsigned char> message(str.begin(), str.end());
    std::cout << "message: " << message[0] << std::endl;
    Signature sign = user.signature(message);

    std::string userId_fake = "user2";

    // 署名の検証
    // bool valid = user.verification(message, userId_fake, params, sign);
    bool valid = user.verification(message, userId, params, sign);

    if (valid) {
        printf("Signature is valid.\n");
    } else {
        printf("Signature is invalid.\n");
    }

    return 0;
}