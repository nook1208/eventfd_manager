CC := $(CROSS_COMPILE)g++
CFLAGS := -g #debugging option

main: main.cpp
	$(CC) $(CFLAGS) main.cpp -o main

clean:
	rm -f main
