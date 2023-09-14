CC = gcc
CFLAGS = -I/usr/include/openssl
LDFLAGS = -L/usr/include/openssl/lib
LIBS = -lcrypto -lssl

all: sha1test server client libpincrack.a  pincracktest

sha1test: sha1test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o sha1test sha1test.c $(LIBS)

server: server.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o server server.c $(LIBS)

client: client.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o client client.c $(LIBS)

libpincrack.a: pincrack.c
	$(CC) -c -o pincrack.o pincrack.c $(CFLAGS)
	ar rcs libpincrack.a pincrack.o



pincracktest: libpincrack.a  pincracktest.c
	$(CC) -o pincracktest pincracktest.c -L. -lpincrack $(LDFLAGS) $(LIBS) 

trace_pincracktest: pincracktest
	strace -T -o output.log ./pincracktest 356a192b7913b04c54574d18c28d46e6395428ab 

clean:
	rm -f sha1test server client pincracktest pincrack.o libpincrack.a pincracktest.output

.PHONY: all clean trace_pincracktest
