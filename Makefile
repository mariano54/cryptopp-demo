all: main

main: main.o
	g++ -o main main.o device_crypto.o util.o -L/home/marianos/Projects/crypto++/cryptopp600 -lcryptopp -ltomcrypt 

main.o: main.cpp
	g++ -c main.cpp device_crypto.cpp util.cpp -L/home/marianos/Projects/crypto++/cryptopp600

run: main
	./main

clean:
	rm -f main *.o
