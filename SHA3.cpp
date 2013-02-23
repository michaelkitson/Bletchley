#include <cstring>
#include <iostream>
#include "SHA3.h"

// Circular rotate left
#define ROT_L( X, Y ) (( X << Y ) | ( X >> (64 - Y) ))
#define ROUNDS 24

/// For converting binary output to hexidecimal for printing
const char *hexLookup = "0123456789abcdef";

const keccakLane_t roundConstants[] = {
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
};

SHA3::SHA3( int digestSize ) : _digestSize( digestSize ){
    // zero the state
    // CHANGE: Now uses bit shifting instead of multiplication
    _spongeCapacity = _digestSize << 4;
    _spongeRate = 1600 - _spongeCapacity;
    _messageBuffer = new unsigned char[_spongeRate];
    _reset();
}

SHA3::~SHA3(){
    // CHANGE: Deconstructor included
    delete[] _messageBuffer;
}
////////// Accessors //////////

int SHA3::digestSize(){
    return _digestSize;
}

////////// Ingesting Data //////////

void SHA3::hash( const int b ){
    _bufferLocation[0] = (unsigned char)b;
    _bufferLocation++;
    if( _bufferLocation == &_messageBuffer[_spongeRate>>3] ){
        _bufferLocation = _messageBuffer;
        _absorbBuffer();
    }
}

void SHA3::hashString( const char *str ){
    int byte = 0;
    while( str[byte] != '\0' ){
        hash( (int)( (unsigned char) str[byte] ) );
        byte++;
    }
}

void SHA3::hashHexString( const char *str ){
    int byte = 0;
    while( str[byte] != '\0' ){
        int f = str[byte];
        int s = str[byte+1];
        if( f >= 97 ) f -= 87; // lowercase
        else if( f >= 65 ) f -= 55; // uppercase
        else f -= 48; // numeric

        if( s >= 97 ) s -= 87; // lowercase
        else if( s >= 65 ) s -= 55; // uppercase
        else s -= 48; // numeric

        hash( (f << 4) | s );
        byte+=2;
    }
}

////////// Expelling Data //////////

void SHA3::digest( unsigned char d[] ){
    // Pad with 10*1 padding
    _bufferLocation[0] = 1;
    _bufferLocation++;
    // CHANGE: Uses system bzero function instead of while loop to initilize
    bzero( _bufferLocation, &_messageBuffer[_spongeRate>>3] - _bufferLocation );
    _messageBuffer[(_spongeRate >> 3) - 1] |= 0x80;
    _absorbBuffer();

    // Squeeze
    memcpy( d, _state, digestSize() );
    _reset(); // Ready the function to hash another message
}

char *SHA3::digestInHex(){
    unsigned char *bytes = new unsigned char[ digestSize() ];
    char *hex = new char[ (digestSize() << 1) + 1 ];

    // CHANGE: Uses bitshifting instead of multiplication
    hex[digestSize() << 1] = '\0';
    digest( bytes );

    for( int byte = 0; byte < digestSize(); byte++ ){
        // CHANGE: Uses bitshifting instead of multiplication
        hex[byte << 1]   = hexLookup[bytes[byte] >> 4];
        hex[(byte << 1)+1] = hexLookup[bytes[byte] & 15];
    }
    delete[] bytes;
    return hex;
}

////////// Internals //////////

inline void SHA3::_reset(){
    // CHANGE: Uses system bzero function instead of while loop to initilize
    bzero( _state, 200 ); //25 64-byte lanes
    _bufferLocation = _messageBuffer;
}

void SHA3::_absorbBuffer(){
    keccakLane_t *x = (keccakLane_t *)_messageBuffer;
    for( int i = 0; i*64 < _spongeRate; i++ ){
        _state[i] |= x[i]; // TODO: unroll
    }
    _performRounds( ROUNDS );
}

// CHANGE: Function changed to inline
inline void SHA3::_performRounds( int rounds ){
    keccakLane_t b[25];
    keccakLane_t c[5];
    keccakLane_t d[5];

    for( int i = 0; i < rounds; i++ ){

        //CHANGE: For loops change to pre-determined steps, reduces call stack

        // Theta step
        c[0] = _state[0] ^ _state[5] ^ _state[10] ^ _state[15] ^ _state[20];
        c[1] = _state[1] ^ _state[6] ^ _state[11] ^ _state[16] ^ _state[21];
        c[2] = _state[2] ^ _state[7] ^ _state[12] ^ _state[17] ^ _state[22];
        c[3] = _state[3] ^ _state[8] ^ _state[13] ^ _state[18] ^ _state[23];
        c[4] = _state[4] ^ _state[9] ^ _state[14] ^ _state[19] ^ _state[24];

        d[0] = c[4] ^ ROT_L( c[1], 1 );
        d[1] = c[0] ^ ROT_L( c[2], 1 );
        d[2] = c[1] ^ ROT_L( c[3], 1 );
        d[3] = c[2] ^ ROT_L( c[4], 1 );
        d[4] = c[3] ^ ROT_L( c[0], 1 );

        _state[0] ^= d[0];
        _state[1] ^= d[1];
        _state[2] ^= d[2];
        _state[3] ^= d[3];
        _state[4] ^= d[4];
        _state[5] ^= d[0];
        _state[6] ^= d[1];
        _state[7] ^= d[2];
        _state[8] ^= d[3];
        _state[9] ^= d[4];
        _state[10] ^= d[0];
        _state[11] ^= d[1];
        _state[12] ^= d[2];
        _state[13] ^= d[3];
        _state[14] ^= d[4];
        _state[15] ^= d[0];
        _state[16] ^= d[1];
        _state[17] ^= d[2];
        _state[18] ^= d[3];
        _state[19] ^= d[4];
        _state[20] ^= d[0];
        _state[21] ^= d[1];
        _state[22] ^= d[2];
        _state[23] ^= d[3];
        _state[24] ^= d[4];

        // Rho and Pi steps
        b[0] = _state[0]; // rotate left by 0 bits
        b[8] = ROT_L( _state[5], 36 );
        b[11] = ROT_L( _state[10], 3 );
        b[19] = ROT_L( _state[15], 41 );
        b[22] = ROT_L( _state[20], 18 );

        b[2] = ROT_L( _state[1], 1 );
        b[5] = ROT_L( _state[6], 44 );
        b[13] = ROT_L( _state[11], 10 );
        b[16] = ROT_L( _state[16], 45 );
        b[24] = ROT_L( _state[21], 2 );

        b[4] = ROT_L( _state[2], 62 );
        b[7] = ROT_L( _state[7], 6 );
        b[10] = ROT_L( _state[12], 43 );
        b[18] = ROT_L( _state[17], 15 );
        b[21] = ROT_L( _state[22], 61 );

        b[1] = ROT_L( _state[3], 28 );
        b[9] = ROT_L( _state[8], 55 );
        b[12] = ROT_L( _state[13], 25 );
        b[15] = ROT_L( _state[18], 21 );
        b[23] = ROT_L( _state[23], 56 );

        b[3] = ROT_L( _state[4], 27 );
        b[6] = ROT_L( _state[9], 20 );
        b[14] = ROT_L( _state[14], 39 );
        b[17] = ROT_L( _state[19], 8 );
        b[20] = ROT_L( _state[24], 14 );

        // Chi step
        _state[0] = b[0] ^ ((~b[5]) & b[10]);
        _state[5] = b[1] ^ ((~b[6]) & b[11]);
        _state[10] = b[2] ^ ((~b[7]) & b[12]);
        _state[15] = b[3] ^ ((~b[8]) & b[13]);
        _state[20] = b[4] ^ ((~b[9]) & b[14]);

        _state[1] = b[5] ^ ((~b[10]) & b[15]);
        _state[6] = b[6] ^ ((~b[11]) & b[16]);
        _state[11] = b[7] ^ ((~b[12]) & b[17]);
        _state[16] = b[8] ^ ((~b[13]) & b[18]);
        _state[21] = b[9] ^ ((~b[14]) & b[19]);

        _state[2] = b[10] ^ ((~b[15]) & b[20]);
        _state[7] = b[11] ^ ((~b[16]) & b[21]);
        _state[12] = b[12] ^ ((~b[17]) & b[22]);
        _state[17] = b[13] ^ ((~b[18]) & b[23]);
        _state[22] = b[14] ^ ((~b[19]) & b[24]);

        _state[3] = b[15] ^ ((~b[20]) & b[0]);
        _state[8] = b[16] ^ ((~b[21]) & b[1]);
        _state[13] = b[17] ^ ((~b[22]) & b[2]);
        _state[18] = b[18] ^ ((~b[23]) & b[3]);
        _state[23] = b[19] ^ ((~b[24]) & b[4]);

        _state[4] = b[20] ^ ((~b[0]) & b[5]);
        _state[9] = b[21] ^ ((~b[1]) & b[6]);
        _state[14] = b[22] ^ ((~b[2]) & b[7]);
        _state[19] = b[23] ^ ((~b[3]) & b[8]);
        _state[24] = b[24] ^ ((~b[4]) & b[9]);

        // Iota step
        _state[0] ^= roundConstants[i];
    }
}

////////// Debugging Functions //////////

void SHA3::_printMessageBuffer(){
    std::cout << "mb = [ ";
    for( int i = 0; i < _spongeRate/8; i++ ){
        std::cout << (int)_messageBuffer[i] << " ";
    }
    std::cout << "]" << std::endl;
}

void SHA3::_printSponge(){
    std::cout << "s = [ " << std::hex;
    for( int x = 0; x < 5; x++ ){
        for( int y = 0; y < 5; y++ ){
            std::cout << _state[x][y] << " ";
        }
    }
    std::cout << std::dec << "]" << std::endl;
}
