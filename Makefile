CC = g++
CFLAGS = -g

main: main.cpp
	$(CC) $(CFLAGS) main.cpp -o main

clean:
	rm -f main
