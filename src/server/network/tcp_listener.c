#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <pthread.h>
#include "tcp_listener.h"
#include "../managers/client/client_manager.h"
#include "../../crypto/protocol/pel.h"
#include "../../client/client.h"

/* 外部全局变量（由core/daemon.c定义） */
extern int daemon_running;
extern int network_fd;

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    client_manager_t *client_mgr;
} client_context_t;

void* network_listener_thread(void* arg) {
    client_manager_t *client_mgr = (client_manager_t*)arg;

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    network_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (network_fd < 0) {
        return NULL;
    }

    if (setsockopt(network_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(network_fd);
        return NULL;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(network_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(network_fd);
        return NULL;
    }

    if (listen(network_fd, 10) < 0) {
        close(network_fd);
        return NULL;
    }

    while (daemon_running) {
        int client_fd = accept(network_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        pthread_t client_thread;
        client_context_t *ctx = malloc(sizeof(client_context_t));
        if (!ctx) {
            perror("malloc");
            close(client_fd);
            continue;
        }

        ctx->client_fd = client_fd;
        ctx->client_addr = client_addr;
        ctx->client_mgr = client_mgr;

        if (pthread_create(&client_thread, NULL, handle_client_connection, ctx) != 0) {
            perror("pthread_create");
            free(ctx);
            close(client_fd);
            continue;
        }

        pthread_detach(client_thread);
    }

    close(network_fd);
    return NULL;
}

void* handle_client_connection(void* arg) {
    client_context_t *ctx = (client_context_t*)arg;
    int client_fd = ctx->client_fd;
    char *secret = SECRET;
    int ret;
    int client_id = -1;  // 初始化为-1，表示尚未添加到管理器

    /* 使用临时上下文进行握手和初始通信 */
    struct pel_context temp_send_ctx, temp_recv_ctx;
    unsigned char temp_buffer[PEL_BUFFER_SIZE];

    /* 第一步: PEL握手验证 - 使用临时上下文 */
    ret = pel_server_init(client_fd, secret, &temp_send_ctx, &temp_recv_ctx);
    if (ret != PEL_SUCCESS) {
        goto cleanup;
    }

    /* 第二步: 接收客户端信息 - 使用临时上下文 */
    unsigned char hostname_buf[64];
    int hostname_len;
    ret = pel_recv_msg(client_fd, hostname_buf, &hostname_len, &temp_recv_ctx, temp_buffer);
    if (ret != PEL_SUCCESS) {
        goto cleanup;
    }
    hostname_buf[hostname_len] = '\0';

    unsigned char os_buf[128];
    int os_len;
    ret = pel_recv_msg(client_fd, os_buf, &os_len, &temp_recv_ctx, temp_buffer);
    if (ret != PEL_SUCCESS) {
        goto cleanup;
    }
    os_buf[os_len] = '\0';

    /* 第三步: 验证成功后添加到客户端管理器，传入hostname用于NAT环境检测 */
    client_id = add_client(ctx->client_mgr, client_fd, &ctx->client_addr, (char*)hostname_buf);
    if (client_id < 0) {
        goto cleanup;
    }

    /* 第四步: 查找并更新客户端信息，包括复制PEL上下文 */
    client_info_t *my_client = NULL;
    for (int i = 0; i < ctx->client_mgr->client_count; i++) {
        if (ctx->client_mgr->clients[i].client_id == client_id) {
            my_client = &ctx->client_mgr->clients[i];

            /* 更新OS信息 (hostname已在add_client中设置) */
            snprintf(my_client->os, MAX_OS_LEN, "%s", (char*)os_buf);

            /* 复制临时上下文到客户端结构 - 关键步骤！ */
            memcpy(&my_client->send_ctx, &temp_send_ctx, sizeof(struct pel_context));
            memcpy(&my_client->recv_ctx, &temp_recv_ctx, sizeof(struct pel_context));

            break;
        }
    }

    // 保持连接开放，等待来自管理终端的命令
    // 实现线程协调机制，避免与管理终端的shell/文件传输冲突
    while (1) {
        // 检查是否有管理终端正在使用此客户端
        if (my_client && (my_client->in_shell_mode || my_client->in_file_transfer)) {
            usleep(100000);
            continue;
        }

        // 简单的保活检查 - 每30秒检查一次连接状态
        fd_set readfds;
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);

        timeout.tv_sec = 30;
        timeout.tv_usec = 0;

        int activity = select(client_fd + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            break;
        } else if (activity == 0) {
            // 超时 - 30秒内无数据，继续等待
            continue;
        } else if (FD_ISSET(client_fd, &readfds)) {
            // 双重检查模式：第一次检查协调标志
            if (my_client && (my_client->in_shell_mode || my_client->in_file_transfer)) {
                continue;
            }

            // 客户端有数据，使用MSG_PEEK检测
            char test_buffer[1];
            int n = recv(client_fd, test_buffer, 1, MSG_PEEK | MSG_DONTWAIT);
            if (n <= 0) {
                break; 
            }

            // 再次检查协调标志，防止竞态窗口期内状态变化
            if (my_client && (my_client->in_shell_mode || my_client->in_file_transfer)) {
                continue;
            }

            // 如果有数据但我们这里不处理，说明客户端发送了意外数据
            // 这种情况下仅检测连接状态，不认为是有效活动
            // 真正的活动更新应该在shell/get/put等命令执行时进行
        }
    }

cleanup:

    if (client_id >= 0) {
        disconnect_client(ctx->client_mgr, client_id);
    }

    close(client_fd);
    free(ctx);
    return NULL;
}
