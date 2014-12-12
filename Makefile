CC=g++
CFLAGS=-Wall

packets: pcap_example.c
	$(CC) -o packets pcap_example.c $(CFLAGS) -lpcap
	
clean:
	rm -rf *o
