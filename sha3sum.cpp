#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include "HashFunction.h"
#include "SHA3.h"

#define DEFAULT_DIGEST_BITS 256
#define FILE_BUFFER_BYTES 4096

void usage(){
    std::cout << "Usage: sha3sum [-a <digestSize>] <file>" << std::endl 
              << "digestSize defaults to " << DEFAULT_DIGEST_BITS << " bits" << std::endl;
}

char *hexDigestForFile( const char *filename, const int digestBytes ){
    std::ifstream file;
    char buffer[FILE_BUFFER_BYTES];
    int amountRead;

    SHA3 sha3( digestBytes );
    HashFunction *hash = &sha3;

    file.open( filename, std::ifstream::in );
    if( !file.is_open() ){
        return 0;
    }
    while( file.good() && amountRead > 0 ){
        amountRead = file.readsome( buffer, FILE_BUFFER_BYTES );
        for( int i = 0; i < amountRead; i++ ){
            hash->hash( (int) ((unsigned char) buffer[i]) );
        }
    }
    file.close();

    unsigned char *digest = new unsigned char[digestBytes];
    char *hexDigest = new char[2*digestBytes + 1];
    char *hexLookup = (char*)"0123456789abcdef";
    hexDigest[2*digestBytes] = '\0';
    hash->digest( digest );
    for( int byte = 0; byte < digestBytes; byte++ ){
        hexDigest[2*byte]   = hexLookup[digest[byte] >> 4];
        hexDigest[(2*byte)+1] = hexLookup[digest[byte] & 15];
    }
    delete( digest );
    return hexDigest;
}

int main( int argc, char *argv[] ){
    char *filename;
    int digestSize;

    if( argc == 2 ){
        digestSize = DEFAULT_DIGEST_BITS;
        filename = argv[1];
    }
    else if( argc == 4 && strcmp( argv[1], "-a" ) == 0 ){
        digestSize = atoi( argv[2] );
        if( digestSize <= 0 ){
            std::cout << digestSize << " is not a valid SHA3 digest length" << std::endl;
            return 1;
        }
        filename = argv[3];
    }
    else{
        usage();
        return 0;
    }

    char *hexDigest = hexDigestForFile( filename, digestSize/8 );
    if( hexDigest != 0 ){
        std::cout << hexDigest << "\t" << filename << std::endl;
    }
    else{
        std::cout << "Couldn't open file: " << filename << std::endl;
    }
    delete( hexDigest );
    return 0;
}
