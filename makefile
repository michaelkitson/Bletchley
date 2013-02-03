flags = -ggdb -Wall

all: TestSHA3 HashSHA3 HashZeroBytes LongTest

TestSHA3: TestSHA3.o SHA3.o
	g++ $(flags) -o TestSHA3 TestSHA3.o SHA3.o

HashSHA3: HashSHA3.o SHA3.o
	g++ $(flags) -o HashSHA3 HashSHA3.o SHA3.o

HashZeroBytes: HashZeroBytes.o SHA3.o
	g++ $(flags) -o HashZeroBytes HashZeroBytes.o SHA3.o

LongTest: LongTest.o SHA3.o
	g++ $(flags) -o LongTest LongTest.o SHA3.o

TestSHA3.o: TestSHA3.cpp
	g++ $(flags) -c TestSHA3.cpp
HashSHA3.o: HashSHA3.cpp
	g++ $(flags) -c HashSHA3.cpp
HashZeroBytes.o: HashZeroBytes.cpp
	g++ $(flags) -c HashZeroBytes.cpp
LongTest.o: LongTest.cpp
	g++ $(flags) -c LongTest.cpp
SHA3.o: SHA3.cpp
	g++ $(flags) -c SHA3.cpp

clean:
	rm TestSHA3.o HashSHA3.o HashZeroBytes.o LongTest.o SHA3.o

realclean: clean
	rm TestSHA3 HashSHA3 HashZeroBytes LongTest
