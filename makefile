CC=gcc
CFLAGS=-W -Wall
LDFLAGS=-lssl -lcrypto
EXEC=crypto

all: $(EXEC)

$(EXEC): cryptomain.o
	$(CC) -o $(EXEC) cryptomain.o $(LDFLAGS)

cryptomain.o: cryptomain.c
	$(CC) -o cryptomain.o -c cryptomain.c $(CFLAGS)

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)