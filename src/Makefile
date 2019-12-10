PROGRAMS = main
CC = gcc
LIB = -lpthread -lnghttp2 -levent -lssl -lcrypto -levent_openssl
FLAGS = -g

all: $(PROGRAMS)

clean:
	rm -rf *.o $(PROGRAMS)

main: main.o url_parser.o ssl.o utils.o http2.o callbacks.o
	$(CC) main.o url_parser.o ssl.o utils.o http2.o callbacks.o -o $(PROGRAMS) $(FLAGS) $(LIB)
main.o: main.c
	$(CC) main.c -c -g
url_parser.o: url_parser.c
	$(CC) url_parser.c -c -g
ssl.o: ssl.c
	$(CC) ssl.c -c -g
utils.o: utils.c
	$(CC) utils.c -c -g
http2.o: http2.c
	$(CC) http2.c -c -g
callbacks.o: callbacks.c
	$(CC) callbacks.c -c -g