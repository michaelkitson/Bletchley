# Team Bletchley
Implementation of the SHA-3 winning algorithm, Keccak, for RIT Computer Science's Crypto class (4003-482).

Specifically, this is a 64-bit implementation of Keccak-1600. It does not support other lane sizes or architectures.
## Team Members
* Christopher Bentivenga
* Frederick Christie
* Michael Kitson

## Usage
Hashing a string:
```sh
$ ./HashSHA3 512 'The quick brown fox jumps over the lazy dog'
Performing SHA3-512 on: 'The quick brown fox jumps over the lazy dog'
d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609
```
Hashing a file:
```sh
$ ./sha3sum -a 256 sha3sum.cpp 
e0a876dbcaac7d97a83e95e40cfd901b09afbc868834ca2793b7835e09bc371d  sha3sum.cpp
```
## Timing on an i7-2677M (OSX 10.8.2 GCC 4.2.1)
### Example timed hashing 2.1 GB of zeros
#### Unoptimized
```sh
$ time ./HashZeroBytes 2100000000

real  9m45.061s
user  9m44.562s
sys	0m0.198s

```
#### Unoptimized -O3
```sh
$ time ./HashZeroBytes 2100000000

real  2m15.476s
user	2m15.362s
sys	0m0.049s

```
#### Optimized
```sh
$ time ./HashZeroBytes 2100000000

real  1m26.483s
user	1m26.338s
sys	0m0.064s
```
#### Optimized -O3
```sh
$ time ./HashZeroBytes 2100000000

real  0m59.322s
user	0m59.230s
sys	0m0.040s
```
### Example hashing of 3500000 8K messages (28 GB) of pseudorandom data
#### Unoptimized
```sh
$ time ./LongTest 3500000

real  17m45.757s
user	17m44.328s
sys	0m0.565s

```
#### Unoptimized -O3
```sh
$ time ./LongTest 3500000

real  3m59.650s
user	3m59.392s
sys	0m0.109s
```
#### Optimized
```sh
$ time ./LongTest 3500000

real  2m37.313s
user	2m37.124s
sys	0m0.079s
```
#### Optimized -O3
```sh
$ time ./LongTest 3500000

real  1m36.851s
user	1m36.728s
sys	0m0.046s
```
## Timing on an Xeon X5560 (glados.cs.rit.edu gcc 4.6.3)
### Example timed hashing 2.1GB of zeros
#### Unoptimized
```sh
$ time ./HashZeroBytes 2100000000

real  13m41.416s
user  13m38.931s
sys	0m0.100s
```
#### Unoptimized -O3
```sh
$ time ./HashZeroBytes 2100000000

real  3m40.460s
user	3m39.898s
sys	0m0.100s
```
#### Optimized
```sh
$ time ./HashZeroBytes 2100000000

real  4m31.554s
user	4m30.937s
sys	0m0.032s

```
#### Optimized -O3
```sh
$ time ./HashZeroBytes 2100000000

real  2m19.864s
user	2m19.545s
sys	0m0.008s
```
### Example hashing of 3500000 8K messages (28 GB) of pseudorandom data
#### Unoptimized
```sh
$ time ./LongTest 3500000

real  24m37.451s
user	24m34.152s
sys	0m0.316s
```
#### Unoptimized -O3
```sh
$ time ./LongTest 3500000

real  6m40.771s
user	6m39.381s
sys	0m0.380s
```
#### Optimized
```sh
$ time ./LongTest 3500000

real  8m11.920s
user	8m10.779s
sys	0m0.100s
```
#### Optimized -O3
```sh
$ time ./LongTest 3500000

real  4m15.848s
user	4m15.312s
sys	0m0.000s
```
