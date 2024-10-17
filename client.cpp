#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <cerrno>

#define TEST_MSG "test_msg"
#define BUFF_SIZE 128

int main(int argc, char **argv) {
	int client_socket;
	struct sockaddr_in server_addr;
	char send_buf[BUFF_SIZE] = TEST_MSG;
	char recv_buf[BUFF_SIZE];

	printf("argc: %d\n", argc);

	if (argc && argv[1]) {
		printf("input: %s\n", argv[1]);
	} else {
		printf("there is no input IP\n");
		return -1;
	}

	client_socket = socket(PF_INET, SOCK_STREAM, 0);

	if (client_socket == -1) {
		printf("failed to create server_socket\n");
		exit(1);
	}

	memset(&server_addr, 0, sizeof( server_addr));
	server_addr.sin_family      = AF_INET;
	server_addr.sin_port        = htons(4000);
	server_addr.sin_addr.s_addr = inet_addr(argv[1]);

	if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		printf("connect failed\n");
		printf("cannot connect to %s: %s", argv[1], strerror(errno));

		exit(1);
	}

	printf("[client] let's send: %s\n", send_buf);
	send(client_socket, send_buf, strlen(TEST_MSG)+1, 0); // +1: NULL까지 포함해서 전송
	recv(client_socket, recv_buf, BUFF_SIZE, 0);
	printf("[client] recv_buf: %s\n", recv_buf);

	close(client_socket);

	return 0;
}


