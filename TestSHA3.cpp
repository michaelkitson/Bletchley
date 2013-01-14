#include <iostream>
#include "HashFunction.h"
#include "SHA3.h"

struct TestCase{
    const int  digestBits;
    const bool hex;          // True if the input is in hexadecimal
    const int  inputRepeats; // Number of times to add the input (minimum 1)
    const char *testString;
    const char *expectedHex;
};

const char *testString1 = "";
const char *testString2 = "The quick brown fox jumps over the lazy dog";
const char *testString3 = "The quick brown fox jumps over the lazy dog.";

// All from the wikipedia SHA-3 page
TestCase testCases[] = {
    {224, false, 1, testString1, "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd"},
    {256, false, 1, testString1, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
    {384, false, 1, testString1, "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff"},
    {512, false, 1, testString1, "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"},

    {224, false, 1, testString2, "310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe"},
    {256, false, 1, testString2, "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"},
    {384, false, 1, testString2, "283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3"},
    {512, false, 1, testString2, "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609"},

    {224, false, 1, testString3, "c59d4eaeac728671c635ff645014e2afa935bebffdb5fbd207ffdeab"},
    {256, false, 1, testString3, "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d"},
    {384, false, 1, testString3, "9ad8e17325408eddb6edee6147f13856ad819bb7532668b605a24a2d958f88bd5c169e56dc4b2f89ffd325f6006d820b"},
    {512, false, 1, testString3, "ab7192d2b11f51c7dd744e7b3441febf397ca07bf812cceae122ca4ded6387889064f8db9230f173f6d1ab6e24b6e50f065b039f799f5592360a6558eb52d760"}
};

bool test( TestCase *testCase ){
    bool result = true;
    SHA3 sha3( testCase->digestBits / 8 );
    int repeats = testCase->inputRepeats;
    while( repeats-- ){
        if( testCase->hex ){
            sha3.hashHexString( testCase->testString );
        }
        else{
            sha3.hashString( testCase->testString );
        }
    }
    char *actualHex = sha3.digestInHex();

    if( strcmp( actualHex, testCase->expectedHex ) != 0 ){
        result = false;
        std::cout << "Expected: " << testCase->expectedHex << " got: " << actualHex << std::endl;
    }
    delete( actualHex );
    return result;
}

int main(){
    bool pass = true;
    for( int i = 0; i < 12; i++ ){
        pass &= test( &testCases[i] );
    }
    std::cout <<  (pass ? "PASS" : "FAIL") << std::endl;
}
