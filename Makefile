all: main

main: main.o
	g++ -o main main.o -L/home/marianos/Projects/crypto++/cryptopp600 -lcryptopp -ltomcrypt 

main.o: main.cpp
	g++ -c main.cpp -L/home/marianos/Projects/crypto++/cryptopp600

run: main
	./main