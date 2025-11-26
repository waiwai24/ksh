#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include "daemon.h"
#include "../managers/client/client_manager.h"
#include "../managers/plugin/plugin_manager.h"
#include "../session/session_manager.h"
#include "../session/shell_session.h"
#include "../network/unix_socket.h"
#include "../network/tcp_listener.h"
#include "../utils/output_writer.h"

/* 全局变量 */
int daemon_running = 0;
int server_fd = -1;
int network_fd = -1;
pthread_t network_thread;

void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        daemon_running = 0;
        if (server_fd != -1) {
            close(server_fd);
            unlink(SOCKET_PATH);
        }
        unlink(PID_FILE);
        exit(0);
    }
}

void write_pid_file(pid_t pid) {
    FILE *fp = fopen(PID_FILE, "w");
    if (fp) {
        fprintf(fp, "%d\n", pid);
        fclose(fp);
    }
}

int is_daemon_running() {
    FILE *fp = fopen(PID_FILE, "r");
    if (!fp) return 0;

    pid_t pid;
    if (fscanf(fp, "%d", &pid) != 1) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    if (kill(pid, 0) == 0) return 1;

    unlink(PID_FILE);
    return 0;
}

int create_daemon() {
    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid > 0) {
        return pid;
    }

    umask(0);

    sid = setsid();
    if (sid < 0) {
        perror("setsid");
        return -1;
    }

    if ((chdir("/")) < 0) {
        perror("chdir");
        return -1;
    }

    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd != -1) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        // 暂时保留stderr用于调试
        // dup2(null_fd, STDERR_FILENO);
        if (null_fd > 2) close(null_fd);
    }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    return 0;
}

void* console_handler_thread(void* arg) {
    console_thread_args_t* args = (console_thread_args_t*)arg;
    int client_fd = args->client_fd;
    client_manager_t *client_mgr = args->client_mgr;
    plugin_manager_t *plugin_mgr = args->plugin_mgr;
    free(args);

    session_state_t session;
    init_session_state(&session, client_mgr, plugin_mgr);

    char buffer[INTERNAL_BUFFER_SIZE];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) break;

        buffer[bytes] = '\0';
        int ret = handle_command(client_fd, buffer, &session);

        if (ret == 1) { // quit
            /* 全局退出：关闭daemon */
            daemon_running = 0;

            if (session.mode == SESSION_CLIENT_CONNECTED) {
                exit_client_session(&session);
            }

            /* 关闭server_fd来唤醒主线程的accept() */
            if (server_fd != -1) {
                shutdown(server_fd, SHUT_RDWR);
                close(server_fd);
                server_fd = -1;
            }

            close(client_fd);
            pthread_detach(pthread_self());
            return NULL;
        } else if (ret == 2) { // disconnect
            break;
        } else if (ret == 3) { // shell mode
            /* 进入shell模式 - 实现真正的双向通信 */
            handle_shell_mode(client_fd, &session);

            /* 刷新socket缓冲区，丢弃shell模式后可能残留的数据 */
            char flush_buffer[1024];
            ssize_t flush_bytes;
            while ((flush_bytes = recv(client_fd, flush_buffer, sizeof(flush_buffer), MSG_DONTWAIT | MSG_PEEK)) > 0) {
                /* 使用MSG_PEEK先检测，确认有数据后再真正读取 */
                recv(client_fd, flush_buffer, flush_bytes, MSG_DONTWAIT);
            }
        }

        /* 返回值约定：
         * 0 = 正常处理完成，需要发送提示符
         * 1 = quit
         * 2 = disconnect
         * 3 = shell模式
         * 4 = 已处理并已发送提示符，不需要再发送
         */
        if (ret == 0) {
            /* 使用output_writer统一发送提示符 */
            char prompt_buffer[64];
            output_writer_t writer;
            writer_init(&writer, prompt_buffer, sizeof(prompt_buffer));

            output_mode_t mode = (session.mode == SESSION_CLIENT_CONNECTED)
                                 ? OUTPUT_MODE_CLIENT : OUTPUT_MODE_NORMAL;
            writer_add_prompt(&writer, mode, session.current_client_id);
            writer_flush(&writer, client_fd);
        }
        /* ret == 4 时不发送提示符，因为命令处理函数已经发送 */
    }

    /* 线程退出前清理：如果仍在客户端会话中，需要清除占用标记 */
    if (session.mode == SESSION_CLIENT_CONNECTED) {
        exit_client_session(&session);
    }

    close(client_fd);

    /* 线程自我分离，自动回收资源 */
    pthread_detach(pthread_self());
    return NULL;
}

void daemon_loop(client_manager_t *client_mgr, plugin_manager_t *plugin_mgr) {
    server_fd = create_unix_socket();
    if (server_fd == -1) return;

    daemon_running = 1;

    if (pthread_create(&network_thread, NULL, network_listener_thread, client_mgr) != 0) {
        perror("Failed to create network listener thread");
        close(server_fd);
        return;
    }

    while (daemon_running) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) {
            if (errno == EINTR) continue;
            /* 如果是因为quit关闭了server_fd，正常退出 */
            if (!daemon_running) break;
            perror("accept error");
            break;
        }

        /* 为新连接创建线程参数 */
        console_thread_args_t* args = malloc(sizeof(console_thread_args_t));
        if (!args) {
            perror("Failed to allocate memory for console thread args");
            close(client_fd);
            continue;
        }

        args->client_fd = client_fd;
        args->client_mgr = client_mgr;
        args->plugin_mgr = plugin_mgr;

        /* 创建线程处理该控制台连接 */
        pthread_t console_thread;
        if (pthread_create(&console_thread, NULL, console_handler_thread, args) != 0) {
            perror("Failed to create console handler thread");
            close(client_fd);
            free(args);
            continue;
        }

        /* 主线程不等待，立即回到accept处理下一个连接 */
        /* 子线程会自己detach并清理资源 */
    }

    if (network_fd != -1) {
        close(network_fd);
    }
    pthread_cancel(network_thread);
    pthread_join(network_thread, NULL);

    int local_server_fd = server_fd;
    server_fd = -1;
    if (local_server_fd != -1) {
        close(local_server_fd);
    }
    unlink(SOCKET_PATH);
}
