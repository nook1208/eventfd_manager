CC := $(CROSS_COMPILE)g++
CFLAGS := -g #debugging option

all: eventfd_manager client server

eventfd_manager: main.cpp
	$(CC) $(CFLAGS) main.cpp -o eventfd_manager

client: client.cpp
	$(CC) $(CFLAGS) client.cpp -o client 

server: server.cpp
	$(CC) $(CFLAGS) server.cpp -o server 

clean:
	rm -f eventfd_manager client server
