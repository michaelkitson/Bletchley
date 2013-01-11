#ifndef SHA3_H
#define SHA3_H

#include "HashFunction.h"

/// SHA-3 winning hash algorithm Keccak
///
/// @author: Christopher Bentivenga
/// @author: Frederick Christie
/// @author: Michael Kitson

class SHA3 : public HashFunction{
 public:
    SHA3( int digestSize );

    /// Adds an entire string to the message
    ///
    /// @param  string  The string of bytes to add
    void hashString( const char *string );

    /// Returns a representation of the digest as a hexidecimal string
    ///
    /// @return The hex string, ownership of which is given to the caller
    char *digestInHex();

    // Overridden functions from HashFunction
    int digestSize();
    void hash( const int b );
    void digest( unsigned char d[] );

 private:
    int _digestSize;
};

#endif
