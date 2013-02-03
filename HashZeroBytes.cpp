#include <iostream>
#include "HashFunction.h"
#include "SHA3.h"

// 512-bit digest
#define DIGEST_BYTES 64

int main( int argc, char* argv[]){
    if( argc != 2 ){
        std::cout << "Usage: HashZeroBytes <N>" << std::endl;
        return 1;
    }
    int messageLength = atoi( argv[1] );
    HashFunction *sha3 = new SHA3( DIGEST_BYTES );
    unsigned char digest[DIGEST_BYTES];
    for( int i = 0; i < messageLength; i++ ){
        sha3->hash( 0 );
    }
    sha3->digest( digest );
    return 0;
}
