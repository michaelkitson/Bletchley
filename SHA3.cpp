#include "SHA3.h"

const char *hexLookup = "0123456789abcdef";

SHA3::SHA3( int digestSize ) : _digestSize( digestSize ){

}

int SHA3::digestSize(){
    return _digestSize;
}

void SHA3::hash( const int b ){
    
}

void SHA3::digest( unsigned char d[] ){

}

char *SHA3::digestInHex(){
    unsigned char *bytes = new unsigned char[ digestSize() ];
    char *hex = new char[ 2 * digestSize() ];
    digest( bytes );

    for( int byte = 0; byte < digestSize(); byte++ ){
        hex[2*byte]   = hexLookup[bytes[byte] >> 4];
        hex[2*byte+1] = hexLookup[bytes[byte] & 15];
    }
    return hex;
}

void SHA3::hashString( const char *string ){
    int byte = 0;
    while( string[byte] != '\0' ){
        // CAST ALL THE THINGS -- hash expects an int, of which the lower 8 bits
        // are used, so we don't want to sign extend the byte (although it would
        // be the same thing)
        hash( (int)( (unsigned char) string[byte] ) );
        byte++;
    }
}
