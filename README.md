# IBS
IBS(IDbased-signature)のプログラム
IDNIKS-Elgamal,IDNIKS- ,BF方式,BB1方式のプログラムがあります

g++ -std=c++11 -I../include -I/opt/homebrew/include -L/opt/homebrew/lib -L../lib -lmcl -lcrypto -lgmp -lgmpxx -framework CoreFoundation -w -o idniks-elgamal idniks-elgamal.cpp