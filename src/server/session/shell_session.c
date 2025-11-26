#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include "shell_session.h"
#include "../core/daemon.h"
#include "../../crypto/protocol/pel.h"
#include "../../client/client.h"

/* Shell模式处理函数 */
void handle_shell_mode(int client_fd, session_state_t *session) {
    fd_set rd;
    char buffer[INTERNAL_BUFFER_SIZE];
    int len, ret;
    int just_wrote_to_client = 0;

    /* 找到客户端信息以便稍后清除shell标志（加锁保护） */
    client_info_t *current_client = NULL;
    pthread_mutex_lock(&session->client_mgr->mutex);
    for (int i = 0; i < session->client_mgr->client_count; i++) {
        if (session->client_mgr->clients[i].client_id == session->current_client_id) {
            current_client = &session->client_mgr->clients[i];
            break;
        }
    }
    pthread_mutex_unlock(&session->client_mgr->mutex);

    dprintf(client_fd, "Entering interactive shell mode. Use 'exit' or Ctrl+D to return.\n");

    while (1) {
        FD_ZERO(&rd);

        /* 如果刚写入过管理客户端，本轮不读取它（避免回环） */
        if (!just_wrote_to_client) {
            FD_SET(client_fd, &rd);                      // 管理客户端
        }
        FD_SET(session->current_client_fd, &rd);         // 远程客户端（始终监听）

        int max_fd = (session->current_client_fd > client_fd) ? session->current_client_fd : client_fd;

        /* 使用短超时，确保不会长时间阻塞已写入的数据 */
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000;

        int select_ret = select(max_fd + 1, &rd, NULL, NULL, &tv);

        if (select_ret < 0) {
            dprintf(client_fd, "\nShell select error, exiting shell mode\n");
            break;
        }

        /* 超时或无事件：清除写后标记，继续下一轮 */
        if (select_ret == 0) {
            just_wrote_to_client = 0;
            continue;
        }

        /* 从远程客户端接收数据并转发到管理客户端 */
        if (FD_ISSET(session->current_client_fd, &rd)) {
            /* 使用客户端的PEL上下文和缓冲区 */
            if (!current_client) {
                dprintf(client_fd, "\nInternal error: client context lost\n");
                break;
            }

            ret = pel_recv_msg(session->current_client_fd, session->message_buffer, &len,
                             &current_client->recv_ctx, current_client->pel_buffer);

            if (ret != PEL_SUCCESS) {
                extern int pel_errno;
                if (pel_errno == PEL_CONN_CLOSED) {
                    dprintf(client_fd, "\nRemote shell closed\n");
                } else {
                    dprintf(client_fd, "\nShell communication error\n");
                }
                break;
            }

            /* 检查shell结束信号 */
            if (len == 1 && session->message_buffer[0] == '\0') {
                dprintf(client_fd, "\nShell ended normally\n");
                break;
            }

            /* 直接转发shell输出给管理客户端，保持二进制完整性 */
            if (write(client_fd, session->message_buffer, len) != len) {
                dprintf(client_fd, "\nWrite error to management client\n");
                break;
            }

            /* 设置写后标记：下一轮select不监听client_fd */
            just_wrote_to_client = 1;
            continue;  // 立即开始下一轮循环
        }

        /* 从管理客户端接收数据并转发到远程客户端 */
        if (FD_ISSET(client_fd, &rd)) {
            /* 使用MSG_PEEK先检测数据，确保不是误读 */
            ssize_t peek_bytes = recv(client_fd, buffer, sizeof(buffer) - 1, MSG_PEEK);

            if (peek_bytes <= 0) {
                dprintf(client_fd, "\nManagement client disconnected\n");
                break;
            }

            /* 实际读取数据 */
            ssize_t bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

            if (bytes <= 0) {
                dprintf(client_fd, "\nManagement client disconnected\n");
                break;
            }

            buffer[bytes] = '\0';

            /* 转发用户输入到远程客户端（不再需要启发式过滤） */
            /* 使用客户端的PEL上下文和缓冲区 */
            if (!current_client) {
                dprintf(client_fd, "\nInternal error: client context lost\n");
                break;
            }

            ret = pel_send_msg(session->current_client_fd, (unsigned char*)buffer, bytes,
                             &current_client->send_ctx, current_client->pel_buffer);
            if (ret != PEL_SUCCESS) {
                dprintf(client_fd, "\nFailed to send data to remote client\n");
                break;
            }

            /* 清除写后标记（因为本轮是读取，不是写入） */
            just_wrote_to_client = 0;
        }
    }

    /* 清除shell模式标志（加锁保护） */
    if (current_client) {
        pthread_mutex_lock(&session->client_mgr->mutex);
        current_client->in_shell_mode = 0;
        pthread_mutex_unlock(&session->client_mgr->mutex);
    }

    /* 发送shell模式结束标记 - 返回到client模式而不是normal模式 */
    dprintf(client_fd, "\001CLIENT_MODE:%d\001Shell mode ended. Returning to client session.\n", session->current_client_id);
}
