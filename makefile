CPPFLAGS = -Wall
LDFLAGS = -lstdc++
CXX = g++
CC = g++

all: TestSHA3 HashSHA3 HashZeroBytes LongTest sha3sum

debug: override CPPFLAGS += -ggdb
debug: all

SHA3-o3:
	$(CXX) $(CPPFLAGS) -O3 -c -o SHA3.o SHA3.cpp
o3:  SHA3-o3 all

TestSHA3: TestSHA3.o SHA3.o
HashSHA3: HashSHA3.o SHA3.o
HashZeroBytes: HashZeroBytes.o SHA3.o
LongTest: LongTest.o SHA3.o
sha3sum: sha3sum.o SHA3.o

.PHONY: clean realclean rc debug all o3 SHA3-o3
clean:
	rm SHA3.o TestSHA3.o HashSHA3.o HashZeroBytes.o LongTest.o sha3sum.o
rc: realclean
realclean: clean
	rm TestSHA3 HashSHA3 HashZeroBytes LongTest sha3sum
