#ifndef SHA3_H
#define SHA3_H
#include <cstdlib>
#include <cstdint>
#include "HashFunction.h"

/// SHA-3 winning hash algorithm Keccak
///
/// @author: Christopher Bentivenga
/// @author: Frederick Christie
/// @author: Michael Kitson
/// @author: Khanh Tran

class SHA3
  :public HashFunction
{
public:
  SHA3( int digestSize );
  ~SHA3();

  typedef unsigned char   byte_type;
  typedef ::std::uint64_t word_type;
  /// Adds an entire string to the message
  ///
  /// @param  string  The string of bytes to add
  void hashString( const char *str );

  /// Adds an entire hexidecimal string to the message
  ///
  /// @param  string  The hex string of bytes to add
  void hashHexString( const char *str );

  /// Returns a representation of the digest as a hexidecimal string
  ///
  /// @return The hex string, ownership of which is given to the caller
  char *digestInHex();
    
  // Overridden functions from HashFunction
  int digestSize();
  void hash  (byte_type const b);
  void digest(byte_type d[]);

private:
  void reset();
  void transform();

  ::std::size_t index_;
  ::std::size_t ndigits_;
  ::std::size_t block_size_;
  word_type  state_[25];
  byte_type* block_;
};

#endif
