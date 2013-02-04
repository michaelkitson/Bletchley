CPPFLAGS = -Wall
LDFLAGS = -lstdc++
CXX = g++
CC = g++

all: TestSHA3 HashSHA3 HashZeroBytes LongTest

debug: override CPPFLAGS += -ggdb
debug: all

TestSHA3: TestSHA3.o SHA3.o
HashSHA3: HashSHA3.o SHA3.o
HashZeroBytes: HashZeroBytes.o SHA3.o
LongTest: LongTest.o SHA3.o

.PHONY: clean realclean rc
clean:
	rm SHA3.o TestSHA3.o HashSHA3.o HashZeroBytes.o LongTest.o
rc: realclean
realclean: clean
	rm TestSHA3 HashSHA3 HashZeroBytes LongTest
