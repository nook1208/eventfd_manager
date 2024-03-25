#define _POSIX_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <cassert>
#include <fcntl.h>
#include <sys/eventfd.h>

#define DEFAULT_FOREGROUND     false
#define DEFAULT_PID_FILE       "/tmp/eventfd_manager.pid"
#define DEFAULT_UNIX_SOCK_PATH "/tmp/eventfd_manager_socket"
#define LISTEN_BACKLOG 10

#define PATH_MAX        4096	/* chars in a path name including nul */
#define VM_ID_MAX 128
#define PEER_LIST_MAX VM_ID_MAX

typedef enum Error
{
    ERROR_PEER_LIST_EMPTY = -1,
    ERROR_PEER_NOT_MATCHED = -2,
} Error;

/* used to quit on signal SIGTERM */
static int eventfd_manager_quit;

/* arguments given by the user */
typedef struct Args {
    bool foreground;
    const char *pid_file;
    const char *unix_socket_path;
} Args;

/*
 * Structure storing a peer
 *
 * Each time a peer connects to an eventfd manager, a new
 * Peer structure is created. This peer and all its
 * eventfd is advertised to all connected clients through the connected
 * unix sockets.
 */
typedef struct Peer {
    int vm_id;             /* the vm_id of the peer and index of peer_list in EventfdManager */
    int sock_fd;          /* connected unix sock */
    int eventfd;
} Peer;

/*
 * Structure describing an eventfd manager
 *
 * This structure stores all information related to our eventfd manager: the name
 * of the unix socket and the list of connected peers.
 */
typedef struct EventfdManager {
    char unix_sock_path[PATH_MAX];   /* path to unix socket */
    int sock_fd;                     /* unix sock file descriptor */
    char next_vm_id;          /* vm_id to be given to next peer*/
    std::vector<Peer> peers;
    int host_channel_eventfd; /* eventfd for host channel kernel module*/
} EventfdManager;

typedef struct FDs {
    fd_set set;
    int max_fd; // the highest-numbered file descriptor in any of sets, plus 1
} FDs;


static bool add_peer(EventfdManager* manager, Peer peer) {
    if (manager->peers.size() >= PEER_LIST_MAX) {
        return false;
    }
    manager->peers.push_back(peer);
    return true;
}

static int remove_peer(EventfdManager* manager, uint8_t idx) {
    if (manager->peers.size() == 0) {
        return ERROR_PEER_LIST_EMPTY;
    }

    if (manager->peers.size() <= idx) {
        return ERROR_PEER_NOT_MATCHED;
    }

    manager->peers[idx] = manager->peers.back();
    manager->peers.pop_back();
    return 0;
}

static void
eventfd_manager_usage(const char *progname) {
    printf("[EM] Usage: %s [OPTION]...\n"
           "  -h: show this help\n"
           "  -F: foreground mode (default is to daemonize)\n"
           "  -p <pid-file>: path to the PID file (used in daemon mode only)\n"
           "     default " DEFAULT_PID_FILE "\n",
           progname);
}

static void
eventfd_manager_help(const char *progname)
{
    fprintf(stderr, "[EM] Try '%s -h' for more information.\n", progname);
}

/* parse the program arguments, exit on error */
static void
eventfd_manager_parse_args(Args *args, int argc, char *argv[])
{
    int c;
    uint64_t v;

    while ((c = getopt(argc, argv, "hFp:S:")) != -1) {

        switch (c) {
        case 'h': /* help */
            eventfd_manager_usage(argv[0]);
            exit(0);
            break;

        case 'F': /* foreground */
            args->foreground = true;
            break;

        case 'p': /* pid file */
            args->pid_file = optarg;
            break;

        case 'S': /* unix socket path */
            args->unix_socket_path = optarg;
            break;

        default:
            eventfd_manager_usage(argv[0]);
            exit(1);
            break;
        }
    }
}

static void eventfd_manager_quit_cb(int signum) {
    printf("[EM] eventfd_manager_quit_cb is called!");
    eventfd_manager_quit = 1;
}

static int eventfd_manager_init(EventfdManager *manager, const char *unix_sock_path) {
    int ret;

    memset(manager, 0, sizeof(*manager));

    ret = snprintf(manager->unix_sock_path, sizeof(manager->unix_sock_path),
                   "%s", unix_sock_path);
    if (ret < 0 || ret >= sizeof(manager->unix_sock_path)) {
        fprintf(stderr, "[EM] could not copy unix socket path\n");
        return -1;
    }

    fprintf(stderr, "[EM] create host channel module eventfd\n");

    /* create eventfd */
    ret = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ret < 0) {
        fprintf(stderr, "[EM] cannot create host channel module's eventfd %s\n", strerror(errno));
        return -1;
    }
    manager->host_channel_eventfd = ret;
    printf("[EM] host_channel_eventfd = %d\n", manager->host_channel_eventfd);

    return 0;
}

/* create and bind to the unix socket */
static int eventfd_manager_start(EventfdManager* manager) {
    struct sockaddr_un s_un;
    int sock_fd, ret;

    fprintf(stderr, "[EM] create & bind socket %s\n", manager->unix_sock_path);
    /* create the unix listening socket */
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        fprintf(stderr, "[EM] cannot create socket: %s\n", strerror(errno));
        goto err;
    }

    s_un.sun_family = AF_UNIX;
    ret = snprintf(s_un.sun_path, sizeof(s_un.sun_path), "%s",
                   manager->unix_sock_path);
    if (ret < 0 || ret >= sizeof(s_un.sun_path)) {
        fprintf(stderr, "[EM] could not copy unix socket path\n");
        goto err_close_sock;
    }
    if (bind(sock_fd, (struct sockaddr *)&s_un, sizeof(s_un)) < 0) {
        fprintf(stderr, "[EM] cannot connect to %s: %s\n", s_un.sun_path,
                             strerror(errno));
        goto err_close_sock;
    }

    if (listen(sock_fd, LISTEN_BACKLOG) < 0) {
        fprintf(stderr, "[EM] listen() failed: %s\n", strerror(errno));
        goto err_unlink_sock;
    }

    manager->sock_fd = sock_fd;
    printf("[EM] manager->sock_fd: %d\n", manager->sock_fd);

    return 0;

err_unlink_sock:
    unlink(manager->unix_sock_path);
err_close_sock:
    close(sock_fd);
err:
    return -1;
}

static int send_one_msg(int sock_fd, int64_t peer_id, int fd);

static void free_peer(EventfdManager *manager, uint8_t idx) {
    Peer &peer = manager->peers[idx];
    fprintf(stderr, "[EM] free peer %d\n", peer.vm_id);

    /* advertise the deletion to other peers */
    for (const auto& other_peer: manager->peers) {
        send_one_msg(other_peer.sock_fd, peer.vm_id, -1);
    }

    close(peer.sock_fd);
    close(peer.eventfd);
    remove_peer(manager, idx);
}

/* close connections to clients, the unix socket and the shm fd */
void eventfd_manager_close(EventfdManager *manager)
{
    fprintf(stderr, "[EM] close manager\n");

    for (uint8_t i = 0; i < manager->peers.size(); i++) {
        free_peer(manager, i);
    }

    close(manager->host_channel_eventfd);

    unlink(manager->unix_sock_path);
    close(manager->sock_fd);

    manager->sock_fd = -1;
}

/* get the FDs according to the unix socket and the peer list */
FDs get_fds(const EventfdManager *manager)
{
    FDs fds = {};
    Peer *peer;

    if (manager->sock_fd == -1) {
		printf("[EM] manager->socket_fd is not set");
        return fds;
    }

    FD_SET(manager->sock_fd, &fds.set);
    if (manager->sock_fd >= fds.max_fd) {
        fds.max_fd = manager->sock_fd + 1;
    }

    for (const auto& peer: manager->peers) {
        FD_SET(peer.sock_fd, &fds.set);
        if (peer.sock_fd >= fds.max_fd) {
            fds.max_fd = peer.sock_fd + 1;
        }
    }

    return fds;
}

void set_fd_flag(int fd, int new_flag)
{
    int flag = fcntl(fd, F_GETFL);
    assert(flag != -1);
    flag = fcntl(fd, F_SETFD, flag | new_flag);
    assert(flag != -1);
}

bool exist_vm_id(EventfdManager* manager, int vm_id) {
    for(const auto& peer: manager->peers) {
        if (peer.vm_id == vm_id) {
            return true;
        }
    }

    return false;
}

int get_next_vm_id(EventfdManager* manager) {
    int next_vm_id = -1;

    // The value of uint8_t is set zero when an integer overflow is occurs
    for (uint8_t i = manager->next_vm_id; manager->next_vm_id - 1 != i; i++) {
        if (!exist_vm_id(manager, i)) {
            next_vm_id = i;
            manager->next_vm_id = i + 1;
            return next_vm_id;
        }
    }

    return next_vm_id;
}

/* send message to a client unix socket */
static int send_one_msg(int sock_fd, int64_t peer_id, int fd) {
    int ret;
    struct msghdr msg;
    struct iovec iov[1];
    union {
        struct cmsghdr cmsg;
        char control[CMSG_SPACE(sizeof(int))];
    } msg_control;
    struct cmsghdr *cmsg;

    iov[0].iov_base = &peer_id;
    iov[0].iov_len = sizeof(peer_id);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    /* if fd is specified, add it in a cmsg */
    if (fd >= 0) {
        memset(&msg_control, 0, sizeof(msg_control));
        msg.msg_control = &msg_control;
        msg.msg_controllen = sizeof(msg_control);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    }

    ret = sendmsg(sock_fd, &msg, 0);
    if (ret < 0) {
        fprintf(stderr, "[EM] sendmsg() failed with %s\n", strerror(errno));
        goto err;
    } else if (ret == 0) {
        fprintf(stderr, "[EM] sendmsg() failed\n");
        goto err;
    }

    return 0;
err:
    return -1;
}

static int handle_new_conn(EventfdManager* manager) {
    Peer peer, *other_peer;
    struct sockaddr_un unaddr;
    socklen_t unaddr_len;
    int new_fd, next_vm_id, ret;
    unsigned i;

    /* accept the incoming connection */
    unaddr_len = sizeof(unaddr);
    new_fd = accept(manager->sock_fd, (struct sockaddr *)&unaddr, &unaddr_len);
    if (new_fd < 0) {
        fprintf(stderr, "[EM] cannot accept() %s\n", strerror(errno));
        return -1;
    }

    set_fd_flag(new_fd, O_NONBLOCK);
    peer.sock_fd = new_fd;

    printf("[EM] new peer sock_fd = %d\n", new_fd);

    next_vm_id = get_next_vm_id(manager);
    if (next_vm_id < 0) {
        fprintf(stderr, "[EM] cannot allocate new client vm_id\n");
        close(new_fd);
        return -1;
    }

    peer.vm_id = next_vm_id;
    printf("[EM] new peer vm_id = %d\n", peer.vm_id);

    /* create eventfd */
    ret = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ret < 0) {
        fprintf(stderr, "[EM] cannot create eventfd %s\n", strerror(errno));
        goto fail;
    }

    peer.eventfd = ret;

    printf("[EM] new peer eventfd = %d\n", peer.eventfd);

    /* send peer vm_id and eventfd to peer */
    ret = send_one_msg(peer.sock_fd, peer.vm_id, peer.eventfd);
    if (ret < 0) {
        goto fail;
    }

    /* send host channel's eventfd to peer */
    ret = send_one_msg(peer.sock_fd, -1, manager->host_channel_eventfd);
    if (ret < 0) {
        goto fail;
    }

    /* advertise the new peer to other */
    for (const auto& other_peer: manager->peers) {
        send_one_msg(other_peer.sock_fd, peer.vm_id, peer.eventfd);
    }

    /* advertise the other peers to the new one */
    for (const auto& other_peer: manager->peers) {
        send_one_msg(peer.sock_fd, other_peer.vm_id, other_peer.eventfd);
    }

    manager->peers.push_back(peer);

    printf("[EM] add a new peer successfully vm_id: %d, eventfd: %d\n", peer.vm_id, peer.eventfd);
    return 0;

fail:
    close(peer.eventfd);
    close(peer.sock_fd);
    return -1;
}

/* process incoming messages on the sockets in fd_set */
static int handle_fds(EventfdManager *manager, const FDs fds)
{
    printf("[EM] handle_fds() start\n");
    if (manager->sock_fd < fds.max_fd && FD_ISSET(manager->sock_fd, &fds.set) &&
        handle_new_conn(manager) < 0 && errno != EINTR) {
        printf("[EM] handle_new_conn() failed\n");
        return -1;
    }

    for (uint8_t i = 0; i < manager->peers.size(); i++) {
        // any message from a peer socket result in a close()
        Peer &peer = manager->peers[i];
        if (peer.sock_fd < fds.max_fd && FD_ISSET(peer.sock_fd, &fds.set)) {
            free_peer(manager, i);
        }
    }

        return 0;
    }

/* wait for events on listening eventfd manager unix socket and connected peer sockets */
static int poll_events(EventfdManager *manager)
{
    FDs fds = {};
    int ret = -1;

	printf("[EM] start poll_events()");

    while (!eventfd_manager_quit)
    {
        fds = get_fds(manager);
        if (fds.max_fd == 0) {
            fprintf(stderr, "[EM] There is no any fd\n");
            return -1;
        }

        ret = select(fds.max_fd, &fds.set, NULL, NULL, NULL);

        if (ret < 0) {
            if (errno == EINTR) {
				printf("[EM] ignore EINTR during polling");
                continue;
            }

            fprintf(stderr, "[EM] select error: %s\n", strerror(errno));
            break;
        }
        if (ret == 0) {
            printf("[EM] wait for event..");
            continue;
        }

        if (handle_fds(manager, fds) < 0) {
            fprintf(stderr, "[EM] handle_fds() failed\n");
            break;
        }
    }
	printf("[EM] exit poll_events()");

    return ret;
}

int main(int argc, char *argv[])
{
    EventfdManager manager;
    struct sigaction sa, sa_quit;
    Args args = {
        .foreground = DEFAULT_FOREGROUND,
        .pid_file = DEFAULT_PID_FILE,
        .unix_socket_path = DEFAULT_UNIX_SOCK_PATH,
    };
    int ret = 1;

    /* parse arguments, will exit on error */
    eventfd_manager_parse_args(&args, argc, argv);

    /* Ignore SIGPIPE, see this link for more info:
     * http://www.mail-archive.com/libevent-users@monkey.org/msg01606.html */
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigemptyset(&sa.sa_mask) == -1 ||
        sigaction(SIGPIPE, &sa, 0) == -1) {
        perror("failed to ignore SIGPIPE; sigaction");
        goto err;
    }

    sa_quit.sa_handler = eventfd_manager_quit_cb;
    sa_quit.sa_flags = 0;
    if (sigemptyset(&sa_quit.sa_mask) == -1 ||
        sigaction(SIGTERM, &sa_quit, 0) == -1 ||
        sigaction(SIGINT, &sa_quit, 0) == -1) {
        perror("failed to add signal handler; sigaction");
        goto err;
    }

    /* init the EventfdManager structure */
    if (eventfd_manager_init(&manager, args.unix_socket_path)) {
        fprintf(stderr, "[EM] cannot init evenfd_manager\n");
        goto err;
    }

    /* start the eventfd manager (open unix socket) */
    if (eventfd_manager_start(&manager) < 0) {
        fprintf(stderr, "[EM] cannot bind\n");
        goto err;
    }

    if (!args.foreground) {
        FILE *fp;

        if (daemon(1, 1) < 0) {
            fprintf(stderr, "[EM] cannot daemonize: %s\n", strerror(errno));
            goto err_close;
        }

        /* write pid file */
        fp = fopen(args.pid_file, "w");
        if (fp == NULL) {
            fprintf(stderr, "[EM] cannot write pid file: %s\n", strerror(errno));
            goto err_close;
        }

        fprintf(fp, "%d\n", (int)getpid());
        fclose(fp);
    }

    poll_events(&manager);
    fprintf(stdout, "[EM] eventfd_manager disconnected\n");
    ret = 0;

err_close:
    eventfd_manager_close(&manager);
err:
    return ret;
}
