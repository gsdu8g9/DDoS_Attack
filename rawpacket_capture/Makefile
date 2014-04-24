all: capture.o filter.o parser.o captype.o
	gcc -lm -o capture capture.o filter.o parser.o captype.o -lpcap -I/usr/include/pcap -Wall
#	gcc -o pcap_test pcap_test.c -lpcap -I/usr/include/pcap
	-rm capture.o filter.o parser.o captype.o

capture.o: capture.c
	gcc -c capture.c -lpcap -I/usr/include/pcap -Wall

filter.o: filter.c filter.h
	gcc -c filter.c -Wall

parser.o: parser.c parser.h
	gcc -c parser.c -Wall

captype.o: captype.c captype.h
	gcc -c captype.c -Wall
