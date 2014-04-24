all: main.o threadpool.o send.o checksum.o
	gcc -lm -o ddos main.o threadpool.o send.o checksum.o -lpthread -Wall
	-rm main.o threadpool.o send.o checksum.o

main.o: main.c
	gcc -c main.c -Wall

threadpool.o: threadpool.c threadpool.h
	gcc -c threadpool.c -Wall

send.o: send.c send.h
	gcc -c send.c -Wall

checksum.o: checksum.c checksum.h
	gcc -c checksum.c -Wall
