#include <cstdlib>
#include <iostream>
#include "HashFunction.h"
#include "SHA3.h"

#define DEFAULT_DIGEST_SIZE 512

void usage(){
    std::cout << "Usage: HashSHA3 [digestSize] <string>" << std::endl 
              << "digestSize defaults to " << DEFAULT_DIGEST_SIZE << " bytes" << std::endl;
}

int main( int argc, char *argv[] ){
    char *message;
    int digestSize;

    if( argc == 2 ){
        digestSize = DEFAULT_DIGEST_SIZE;
        message = argv[1];
    }
    else if( argc == 3 ){
        digestSize = atoi( argv[1] );
        if( digestSize <= 0 ){
            std::cout << digestSize << " is not a valid SHA3 digest length" << std::endl;
            return 1;
        }
        message = argv[2];
    }
    else{
        usage();
        return 0;
    }

    std::cout << "Performing SHA3-" << digestSize << " on: '" << message
              << "'" << std::endl;

    SHA3 x( digestSize );
    HashFunction *hasher = &x;
}
