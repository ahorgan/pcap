CC=g++
CFLAGS=-Wall

packets: pcap_example.c
	$(CC) -o packets pcap_example.c $(CFLAGS) -lpcap -Wno-write-strings
	
clean:
	rm -rf *o
