all: TestSHA3 HashSHA3

TestSHA3: TestSHA3.o SHA3.o
	g++ -o TestSHA3 TestSHA3.o SHA3.o

HashSHA3: HashSHA3.o SHA3.o
	g++ -o HashSHA3 HashSHA3.o SHA3.o

HashSHA3.o: HashSHA3.cpp
TestSHA3.o: TestSHA3.cpp
SHA3.o:      SHA3.cpp SHA3.h HashFunction.h

clean:
	rm TestSHA3.o HashSHA3.o SHA3.o

realclean: clean
	rm TestSHA3 HashSHA3
