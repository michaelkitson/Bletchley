#include <cstring>
#include "SHA3.h"

// Circular rotate left
#define ROT_L( X, Y ) (( X << Y ) | ( X >> (64 - Y) ))

SHA3::SHA3(
  int digestSize
):index_(0)
 ,ndigits_(digestSize)
 ,block_size_(200 - 2 * ndigits_)
 ,block_(new unsigned char[block_size_])
{
  reset();
}

SHA3::~SHA3(
) {
  delete[] block_;
}
////////// Accessors //////////

int SHA3::digestSize(
) {
  return (ndigits_);
}

////////// Ingesting Data //////////

void SHA3::hash(
  byte_type const b
) {
  block_[index_++] = b;
  if (index_ == block_size_) {
    transform();
    index_ = 0;
  }
}

void SHA3::hashString(
  char const* _str
) {
  while (*_str != '\0') {
    hash((unsigned char)*_str);
    ++_str;
  }
}

static inline
unsigned char to_hex(
  char _chr
) {
  if (_chr >= 97)
    _chr -= 87; // lowercase
  else
  if (_chr >= 65)
    _chr -= 55; // uppercase
  else
    _chr -= 48; // numeric

  return (_chr);
}

void SHA3::hashHexString(
  char const* str
) {
  while (*str != '\0') {
    unsigned char hi = to_hex(*str++);
    unsigned char lo = to_hex(*str++);
    hash((hi << 4) | lo);
  }
}

////////// Expelling Data //////////

void SHA3::digest(
  byte_type d[]
) {
  // Pad with 10*1 padding
  block_[index_++] = 1;

  while (index_ != block_size_)
    block_[index_++] = 0;

  block_[block_size_ - 1] |= 0x80;
  transform();

  // Squeeze
  ::std::memcpy(d, state_, ndigits_);
  reset(); // Ready the function to hash another message
}

char *SHA3::digestInHex(
) {
  char const* hexLookup = "0123456789abcdef";

  byte_type* bytes = new byte_type[ndigits_];
  char* hex = new char[ndigits_ * 2 + 1];

  digest(bytes);

  for (::std::size_t byte = 0; byte < ndigits_; ++byte) {
    hex[ byte << 1     ] = hexLookup[bytes[byte] >> 4];
    hex[(byte << 1) + 1] = hexLookup[bytes[byte] & 15];
  }
  hex[ndigits_ * 2] = '\0';
  delete[] bytes;

  return (hex);
}

////////// Internals //////////

inline
void SHA3::reset(
) {
  std::memset(state_, 0, 200); //25 64-byte lanes
  index_ = 0;
}

void SHA3::transform(
) {
  static word_type const sc_round_constants_[] =
  {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
  };

  word_type b[25] = {0};
  word_type c[ 5] = {0};
  word_type d[ 5] = {0};

  auto&& s = state_;
  word_type* x = (word_type*)block_;
  for (::std::size_t i = 0; i < (block_size_ >> 3); ++i)
    s[i] ^= x[i];

  for (int i = 0; i < 24; ++i) {

    c[0] = s[ 0] ^ s[ 5] ^ s[10] ^ s[15] ^ s[20];
    c[1] = s[ 1] ^ s[ 6] ^ s[11] ^ s[16] ^ s[21];
    c[2] = s[ 2] ^ s[ 7] ^ s[12] ^ s[17] ^ s[22];
    c[3] = s[ 3] ^ s[ 8] ^ s[13] ^ s[18] ^ s[23];
    c[4] = s[ 4] ^ s[ 9] ^ s[14] ^ s[19] ^ s[24];

    d[0] = c[4] ^ ROT_L(c[1], 1);
    d[1] = c[0] ^ ROT_L(c[2], 1);
    d[2] = c[1] ^ ROT_L(c[3], 1);
    d[3] = c[2] ^ ROT_L(c[4], 1);
    d[4] = c[3] ^ ROT_L(c[0], 1);

    s[ 0] ^= d[0]; s[ 6] ^= d[1]; s[12] ^= d[2]; s[18] ^= d[3]; s[24] ^= d[4];
    s[ 3] ^= d[3]; s[ 9] ^= d[4]; s[10] ^= d[0]; s[16] ^= d[1]; s[22] ^= d[2];
    s[ 1] ^= d[1]; s[ 7] ^= d[2]; s[13] ^= d[3]; s[19] ^= d[4]; s[20] ^= d[0];
    s[ 4] ^= d[4]; s[ 5] ^= d[0]; s[11] ^= d[1]; s[17] ^= d[2]; s[23] ^= d[3];
    s[ 2] ^= d[2]; s[ 8] ^= d[3]; s[14] ^= d[4]; s[15] ^= d[0]; s[21] ^= d[1];

    b[ 0] =       s[ 0]     ; b[ 1] = ROT_L(s[ 6], 44);
    b[ 2] = ROT_L(s[12], 43); b[ 3] = ROT_L(s[18], 21);
    b[ 4] = ROT_L(s[24], 14); b[ 5] = ROT_L(s[ 3], 28);
    b[ 6] = ROT_L(s[ 9], 20); b[ 7] = ROT_L(s[10],  3);
    b[ 8] = ROT_L(s[16], 45); b[ 9] = ROT_L(s[22], 61);
    b[10] = ROT_L(s[ 1],  1); b[11] = ROT_L(s[ 7],  6);
    b[12] = ROT_L(s[13], 25); b[13] = ROT_L(s[19],  8);
    b[14] = ROT_L(s[20], 18); b[15] = ROT_L(s[ 4], 27);
    b[16] = ROT_L(s[ 5], 36); b[17] = ROT_L(s[11], 10);
    b[18] = ROT_L(s[17], 15); b[19] = ROT_L(s[23], 56);
    b[20] = ROT_L(s[ 2], 62); b[21] = ROT_L(s[ 8], 55);
    b[22] = ROT_L(s[14], 39); b[23] = ROT_L(s[15], 41);
    b[24] = ROT_L(s[21],  2);

    s[ 0] = b[ 0] ^ ((~b[ 1]) & b[ 2]); s[ 1] = b[ 1] ^ ((~b[ 2]) & b[ 3]);
    s[ 2] = b[ 2] ^ ((~b[ 3]) & b[ 4]); s[ 3] = b[ 3] ^ ((~b[ 4]) & b[ 0]);
    s[ 4] = b[ 4] ^ ((~b[ 0]) & b[ 1]); s[ 5] = b[ 5] ^ ((~b[ 6]) & b[ 7]);
    s[ 6] = b[ 6] ^ ((~b[ 7]) & b[ 8]); s[ 7] = b[ 7] ^ ((~b[ 8]) & b[ 9]);
    s[ 8] = b[ 8] ^ ((~b[ 9]) & b[ 5]); s[ 9] = b[ 9] ^ ((~b[ 5]) & b[ 6]);
    s[10] = b[10] ^ ((~b[11]) & b[12]); s[11] = b[11] ^ ((~b[12]) & b[13]);
    s[12] = b[12] ^ ((~b[13]) & b[14]); s[13] = b[13] ^ ((~b[14]) & b[10]);
    s[14] = b[14] ^ ((~b[10]) & b[11]); s[15] = b[15] ^ ((~b[16]) & b[17]);
    s[16] = b[16] ^ ((~b[17]) & b[18]); s[17] = b[17] ^ ((~b[18]) & b[19]);
    s[18] = b[18] ^ ((~b[19]) & b[15]); s[19] = b[19] ^ ((~b[15]) & b[16]);
    s[20] = b[20] ^ ((~b[21]) & b[22]); s[21] = b[21] ^ ((~b[22]) & b[23]);
    s[22] = b[22] ^ ((~b[23]) & b[24]); s[23] = b[23] ^ ((~b[24]) & b[20]);
    s[24] = b[24] ^ ((~b[20]) & b[21]);

    s[ 0] ^= sc_round_constants_[i];
  }
}
