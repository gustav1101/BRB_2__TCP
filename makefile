CFLAGS = -Wall -std=c99 -pedantic -D_POSIX_SOURCE -g -lssl -lcrypto
PORT = 25565
ADDRESS = 127.0.0.1
FILEPATH = files/testfile
SRCPATH = src/
BINPATH = bin/
VALGPARAMS = --leak-check=full --track-origins=yes

build: received $(BINPATH)sender_tcp $(BINPATH)receiver_tcp

debug: clearconsole build

$(BINPATH)receiver_tcp: $(SRCPATH)receiver_tcp.c $(SRCPATH)receiver_tcp.h
	gcc $(CFLAGS) -o $(BINPATH)receiver_tcp $(SRCPATH)receiver_tcp.c

$(BINPATH)sender_tcp: $(SRCPATH)sender_tcp.c $(SRCPATH)sender_tcp.h
	gcc $(CFLAGS) -o $(BINPATH)sender_tcp $(SRCPATH)sender_tcp.c	

received:
	mkdir received

clearconsole:
	reset

clean:
	rm bin/* received/*

testrec: build
	$(BINPATH)receiver_tcp $(PORT)

testsend: build
	$(BINPATH)sender_tcp $(ADDRESS) $(PORT) $(FILEPATH)

valgrec: build
	valgrind $(VALGPARAMS) $(BINPATH)receiver_tcp $(PORT)

valgsend: build
	valgrind $(VALGPARAMS) $(BINPATH)sender_tcp $(ADDRESS) $(PORT) $(FILEPATH)

