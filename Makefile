all: main

main: main.o
	g++ -o main main.o device_crypto.o util.o -lcryptopp -ltomcrypt 

main.o: main.cpp
	g++ -c main.cpp device_crypto.cpp util.cpp

run: main
	./main

clean:
	rm -f main *.o
