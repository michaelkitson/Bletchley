#include <iostream>
#include <cstdlib>
#include "HashFunction.h"
#include "SHA3.h"

// 512-bit digest
#define DIGEST_BYTES 64

int main( int argc, char* argv[] ){
    if( argc != 2 ){
        std::cout << "Usage: LongTest <iterations>" << std::endl
                  << "    Iterations is recommended to be > ~400000 to"
                  << " achieve a 100 second runtime" << std::endl;
        return 1;
    }
    int iterations = atoi( argv[1] );

    unsigned char buffer[DIGEST_BYTES];
    for( int i = 0; i < DIGEST_BYTES; i++ ){
        buffer[i] = 0;
    }
    
    HashFunction *sha3 = new SHA3( DIGEST_BYTES );
    for( int i = 0; i < iterations; i++ ){
        // Messages 16 times the digest size (8KB)
        for( int b = 0; b < (DIGEST_BYTES << 4); b++ ){
            sha3->hash( buffer[b % DIGEST_BYTES] );
        }
        sha3->digest( buffer );
    }
    return 0;
}
