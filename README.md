# IBS
IBS(IDbased-signature)のプログラム

IDNIKS-Elgamal,IDNIKS- ,BF方式,BB1方式のプログラムがあります.

g++ -std=c++11 -I../include -I/opt/homebrew/include -L/opt/homebrew/lib -L../lib -lmcl -lcrypto -lgmp -lgmpxx -framework CoreFoundation -w -o idniks-elgamal idniks-elgamal.cpp

g++ -std=c++11 -I../include -I/opt/homebrew/include -L/opt/homebrew/lib -L../lib -lmcl -lcrypto -lgmp -lgmpxx -framework CoreFoundation -w -c idniks-schnorr-kgc.cpp

g++ -std=c++11 -I../include -I/opt/homebrew/include -L/opt/homebrew/lib -L../lib -lmcl -lcrypto -lgmp -lgmpxx -framework CoreFoundation -w -c idniks-schnorr.cpp

g++ -std=c++11 -I../include -I/opt/homebrew/include -L/opt/homebrew/lib -L../lib -lmcl -lcrypto -lgmp -lgmpxx -framework CoreFoundation -w -c idniks-schnorr-user.cpp

g++ -std=c++11 -I../include -I/opt/homebrew/include -L/opt/homebrew/lib -L../lib -lmcl -lcrypto -lgmp -lgmpxx -framework CoreFoundation -w -c idniks-schnorr-test.cpp 

g++ -std=c++11 -I../include -I/opt/homebrew/include -L/opt/homebrew/lib -L../lib -lmcl -lcrypto -lgmp -lgmpxx -framework CoreFoundation -w -c mpz_util_in.cpp

g++ -std=c++11 -I../include -I/opt/homebrew/include -L/opt/homebrew/lib -L../lib -lmcl -lcrypto -lgmp -lgmpxx -framework CoreFoundation -w -o a idniks-schnorr-test.o idniks-schnorr-1.o idniks-schnorr-kgc.o idniks-schnorr-user.o mpz_util.o
