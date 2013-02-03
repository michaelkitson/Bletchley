# Team Bletchley
Implementation of the SHA-3 winning algorithm, Keccak, for RIT Computer Science's Crypto class (4003-482).

Specifically, this is a 64-bit implementation of Keccak-1600. It does not support other lane sizes or architectures.
## Team Members
* Christopher Bentivenga
* Frederick Christie
* Michael Kitson

## Usage
```sh
$ ./HashSHA3 512 'The quick brown fox jumps over the lazy dog'
Performing SHA3-512 on: 'The quick brown fox jumps over the lazy dog'
d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609
```
[Output Verification](https://en.wikipedia.org/wiki/Sha3#Examples_of_SHA-3_.28Keccak.29_variants)

## Timing Functions
### Timing on an i7-2677M
Example timed hashing 100 MiB of zeros
```sh
$ time ./HashZeroBytes 100000000

real  0m18.825s
user  0m18.812s
sys 0m0.008s
```
Example hashing of 400000 8K messages (~3.27 GB) of pseudorandom data
```sh
$ time ./LongTest 400000

real  2m5.592s
user  2m5.331s
sys 0m0.132s
```
