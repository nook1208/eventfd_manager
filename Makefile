CC := $(CROSS_COMPILE)g++
CFLAGS := -g #debugging option

eventfd_manager: main.cpp
	$(CC) $(CFLAGS) main.cpp -o eventfd_manager

clean:
	rm -f eventfd_manager
