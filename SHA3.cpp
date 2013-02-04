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

int rotationOffsets[5][5] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14}
};

SHA3::SHA3( int digestSize ) : _digestSize( digestSize ){
    // zero the state
    _spongeCapacity = 2 * 8 * _digestSize;
    _spongeRate = 1600 - _spongeCapacity;
    _messageBuffer = new unsigned char[_spongeRate];
    _reset();
}

////////// Accessors //////////

int SHA3::digestSize(){
    return _digestSize;
}

////////// Ingesting Data //////////

void SHA3::hash( const int b ){
    _bufferLocation[0] = (unsigned char)b;
    _bufferLocation++;
    if( _bufferLocation == &_messageBuffer[_spongeRate/8] ){
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
    while( _bufferLocation != &_messageBuffer[_spongeRate/8] ){
        _bufferLocation[0] = 0;
        _bufferLocation++;
    }
    _messageBuffer[_spongeRate/8 - 1] |= 0x80;
    _absorbBuffer();

    // Squeeze
    memcpy( d, _state, digestSize() );
    _reset(); // Ready the function to hash another message
}

char *SHA3::digestInHex(){
    unsigned char *bytes = new unsigned char[ digestSize() ];
    char *hex = new char[ 2 * digestSize() + 1 ];
    hex[2*digestSize()] = '\0';
    digest( bytes );

    for( int byte = 0; byte < digestSize(); byte++ ){
        hex[2*byte]   = hexLookup[bytes[byte] >> 4];
        hex[2*byte+1] = hexLookup[bytes[byte] & 15];
    }
    delete( bytes );
    return hex;
}

////////// Internals //////////

void SHA3::_reset(){
    for( int x = 0; x < 5; x++ ){
        for( int y = 0; y < 5; y++ ){
            _state[x][y] = 0;
        }
    }
    _bufferLocation = _messageBuffer;
}

void SHA3::_absorbBuffer(){
    keccakLane_t *x = (keccakLane_t *)_messageBuffer;
    for( int i = 0; i*64 < _spongeRate; i++ ){
        _state[i/5][i%5] |= x[i];
    }
    _performRounds( ROUNDS );
}

void SHA3::_performRounds( int rounds ){
    keccakLane_t b[5][5];
    keccakLane_t c[5];
    keccakLane_t d[5];

    for( int i = 0; i < rounds; i++ ){
        // Theta step
        c[0] = _state[0][0] ^ _state[1][0] ^ _state[2][0] ^ _state[3][0] ^ _state[4][0];
        c[1] = _state[0][1] ^ _state[1][1] ^ _state[2][1] ^ _state[3][1] ^ _state[4][1];
        c[2] = _state[0][2] ^ _state[1][2] ^ _state[2][2] ^ _state[3][2] ^ _state[4][2];
        c[3] = _state[0][3] ^ _state[1][3] ^ _state[2][3] ^ _state[3][3] ^ _state[4][3];
        c[4] = _state[0][4] ^ _state[1][4] ^ _state[2][4] ^ _state[3][4] ^ _state[4][4];

        d[0] = c[4] ^ ROT_L( c[1], 1);
        d[1] = c[0] ^ ROT_L( c[2], 1);
        d[2] = c[1] ^ ROT_L( c[3], 1);
        d[3] = c[2] ^ ROT_L( c[4], 1);
        d[4] = c[3] ^ ROT_L( c[0], 1);

        _state[0][0] ^= d[0];
        _state[0][1] ^= d[1];
        _state[0][2] ^= d[2];
        _state[0][3] ^= d[3];
        _state[0][4] ^= d[4];
        _state[1][0] ^= d[0];
        _state[1][1] ^= d[1];
        _state[1][2] ^= d[2];
        _state[1][3] ^= d[3];
        _state[1][4] ^= d[4];
        _state[2][0] ^= d[0];
        _state[2][1] ^= d[1];
        _state[2][2] ^= d[2];
        _state[2][3] ^= d[3];
        _state[2][4] ^= d[4];
        _state[3][0] ^= d[0];
        _state[3][1] ^= d[1];
        _state[3][2] ^= d[2];
        _state[3][3] ^= d[3];
        _state[3][4] ^= d[4];
        _state[4][0] ^= d[0];
        _state[4][1] ^= d[1];
        _state[4][2] ^= d[2];
        _state[4][3] ^= d[3];
        _state[4][4] ^= d[4];

        // Rho and Pi steps
        for( int x = 0; x < 5; x++ ){
            for( int y = 0; y < 5; y++ ){
                b[y][(2*x + 3*y) % 5] = ROT_L( _state[y][x], rotationOffsets[x][y] );
            }
        }
        // Chi step
        for( int x = 0; x < 5; x++ ){
            for( int y = 0; y < 5; y++ ){
                _state[y][x] = b[x][y] ^ ((~b[(x+1) % 5][y]) & b[(x+2) % 5][y]);
            }
        }
        // Iota step
        _state[0][0] ^= roundConstants[i];
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
