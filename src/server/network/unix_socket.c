#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include "unix_socket.h"
#include "../core/daemon.h"

int create_unix_socket() {
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) return -1;

    unlink(SOCKET_PATH);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(fd);
        return -1;
    }

    if (listen(fd, 5) == -1) {
        close(fd);
        unlink(SOCKET_PATH);
        return -1;
    }

    return fd;
}

int connect_to_daemon() {
    int fd;
    struct sockaddr_un addr;
    int flags;
    fd_set writefds;
    struct timeval timeout;
    int result;
    socklen_t result_len = sizeof(result);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    /* 设置为非阻塞模式 */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        close(fd);
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL");
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /* 非阻塞 connect，可能立即返回 EINPROGRESS */
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        if (errno != EINPROGRESS) {
            perror("connect");
            close(fd);
            return -1;
        }

        /* 等待连接完成，5秒超时 */
        FD_ZERO(&writefds);
        FD_SET(fd, &writefds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        if (select(fd + 1, NULL, &writefds, NULL, &timeout) <= 0) {
            perror("connect timeout");
            close(fd);
            return -1;
        }

        /* 检查连接是否成功 */
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &result, &result_len) == -1) {
            perror("getsockopt");
            close(fd);
            return -1;
        }

        if (result != 0) {
            errno = result;
            perror("connect");
            close(fd);
            return -1;
        }
    }

    /* 恢复阻塞模式 */
    if (fcntl(fd, F_SETFL, flags) == -1) {
        perror("fcntl restore flags");
        close(fd);
        return -1;
    }

    return fd;
}
