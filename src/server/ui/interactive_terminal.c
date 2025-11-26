#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <errno.h>
#include "interactive_terminal.h"
#include "../network/unix_socket.h"

#define INTERNAL_BUFFER_SIZE 16384

void interactive_mode() {
    int daemon_fd;
    char buffer[INTERNAL_BUFFER_SIZE];
    char stdin_buffer[4096];
    fd_set readfds;
    struct timeval timeout;

    daemon_fd = connect_to_daemon();
    if (daemon_fd == -1) {
        printf("Failed to connect to daemon. Is it running?\n");
        return;
    }

    printf("Connected to daemon. Type 'help' for commands.\n");
    printf("\033[31mkshd>\033[0m ");
    fflush(stdout);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(daemon_fd, &readfds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(daemon_fd + 1, &readfds, NULL, NULL, &timeout);
        if (activity < 0) {
            if (errno == EINTR) continue;  // 被信号中断，重试
            perror("select");
            break;
        }

        /* 优先处理daemon的响应（避免stdin阻塞导致的时序问题） */
        if (FD_ISSET(daemon_fd, &readfds)) {
            ssize_t bytes = recv(daemon_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                printf("Daemon disconnected\n");
                break;
            }

            buffer[bytes] = '\0';

            /* 检查是否包含模式信息 */
            char *mode_start = strchr(buffer, '\001');
            if (mode_start) {
                char *mode_end = strchr(mode_start + 1, '\001');
                if (mode_end) {
                    *mode_start = '\0';
                    *mode_end = '\0';

                    if (strlen(buffer) > 0) {
                        printf("%s", buffer);
                    }

                    if (strncmp(mode_start + 1, "CLIENT_MODE:", 12) == 0) {
                        int client_id = atoi(mode_start + 13);
                        printf("\033[32mclient[%d]>\033[0m ", client_id);
                    } else if (strncmp(mode_start + 1, "SHELL_MODE:", 11) == 0) {
                    } else if (strncmp(mode_start + 1, "NORMAL_MODE", 11) == 0) {
                        printf("\033[31mkshd>\033[0m ");
                    } else {
                        printf("\033[31mkshd>\033[0m ");
                    }
                } else {
                    printf("%s", buffer);
                }
            } else {
                printf("%s", buffer);
            }

            fflush(stdout);
        }

        /* 然后处理stdin输入 */
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(stdin_buffer, sizeof(stdin_buffer), stdin) == NULL) break;

            if (send(daemon_fd, stdin_buffer, strlen(stdin_buffer), 0) == -1) {
                perror("send");
                break;
            }

            if (strncmp(stdin_buffer, "quit", 4) == 0 || strncmp(stdin_buffer, "disconnect", 10) == 0) {
                break;
            }
        }
    }

    close(daemon_fd);
}
