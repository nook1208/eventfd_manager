#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <cerrno>

#define BUFF_SIZE 128

int main(int argc, char *argv[]) {
	int server_socket;
	int client_socket;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
    socklen_t client_addr_size;
	char recv_buf[BUFF_SIZE];
	char send_buf[BUFF_SIZE];

	printf("argc: %d\n", argc);

	if (argc && argv[1]) {
		printf("input: %s\n", argv[1]);
	} else {
		printf("there is no input IP\n");
		return -1;
	}

	server_socket = socket(PF_INET, SOCK_STREAM, 0);

	if(server_socket == -1) {
		printf("failed to create server_socket\n");
		exit(1);
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
	server_addr.sin_port        = htons(4000);
	server_addr.sin_addr.s_addr = inet_addr(argv[1]);

	if(bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
		printf("bind() failed \n");
		exit( 1);
	}

	if (daemon(1, 1) < 0) {
		printf("[server] cannot daemonize: %s\n", strerror(errno));
		close(server_socket);
		return -1;
	}

	while(1) {
		if (listen(server_socket, 10) == -1) {
			printf("listen failed \n");
			exit(1);
		}

		client_addr_size = sizeof(client_addr);
		client_socket = accept(server_socket,(struct sockaddr*)&client_addr, &client_addr_size);

		if (client_socket == -1) {
			printf("accept failed\n");
			exit(1);
		}

		recv(client_socket, recv_buf, BUFF_SIZE, 0);
		printf("[server] receive: %s\n", recv_buf);

		snprintf(send_buf, sizeof(send_buf), "%s", recv_buf);
		send(client_socket, send_buf, strlen(send_buf)+1, 0);
		close(client_socket);
	}

	close(server_socket);
	return 0;
}
