#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "session_manager.h"
#include "../commands/management/management_commands.h"
#include "../commands/client/client_commands.h"

void init_session_state(session_state_t *session, client_manager_t *client_mgr, plugin_manager_t *plugin_mgr) {
    session->mode = SESSION_NORMAL;
    session->current_client_id = -1;
    session->current_client_fd = -1;
    session->client_mgr = client_mgr;
    session->plugin_mgr = plugin_mgr;
}

int enter_client_session(session_state_t *session, int client_id) {
    if (!session || !session->client_mgr) {
        return -1;
    }

    /* 查找客户端 */
    client_info_t *client = NULL;
    pthread_mutex_lock(&session->client_mgr->mutex);

    for (int i = 0; i < session->client_mgr->client_count; i++) {
        if (session->client_mgr->clients[i].client_id == client_id) {
            client = &session->client_mgr->clients[i];
            break;
        }
    }

    if (!client || client->client_id == -1) {
        pthread_mutex_unlock(&session->client_mgr->mutex);
        return -2; // 客户端不存在
    }

    if (client->is_alive != 1) {
        pthread_mutex_unlock(&session->client_mgr->mutex);
        return -3; // 客户端未连接
    }

    /* 检查会话占用状态 - 防止多管理员并发冲突 */
    if (client->in_session) {
        pthread_mutex_unlock(&session->client_mgr->mutex);
        return -4; // 客户端已被其他管理员占用
    }

    /* 进入客户端会话并标记占用 */
    session->mode = SESSION_CLIENT_CONNECTED;
    session->current_client_id = client_id;
    session->current_client_fd = client->socket_fd;

    client->in_session = 1;

    pthread_mutex_unlock(&session->client_mgr->mutex);
    return 0;
}

int exit_client_session(session_state_t *session) {
    if (!session) {
        return -1;
    }

    /* 清除会话占用标记 */
    if (session->current_client_id >= 0 && session->client_mgr) {
        pthread_mutex_lock(&session->client_mgr->mutex);

        for (int i = 0; i < session->client_mgr->client_count; i++) {
            if (session->client_mgr->clients[i].client_id == session->current_client_id) {
                session->client_mgr->clients[i].in_session = 0;
                break;
            }
        }

        pthread_mutex_unlock(&session->client_mgr->mutex);
    }

    session->mode = SESSION_NORMAL;
    session->current_client_id = -1;
    session->current_client_fd = -1;

    return 0;
}

int handle_command(int client_fd, char *buffer, session_state_t *session) {
    char *cmd = strtok(buffer, " \t\r\n");
    char *args = strtok(NULL, "\0");

    if (!cmd) return 0;

    /* 去除args开头的空白字符 */
    if (args) {
        while (*args && (*args == ' ' || *args == '\t')) {
            args++;
        }
        /* 去除args结尾的换行符 */
        char *end = args + strlen(args) - 1;
        while (end >= args && (*end == '\r' || *end == '\n')) {
            *end-- = '\0';
        }
    }

    /* 根据会话模式决定命令处理方式 */
    if (session->mode == SESSION_CLIENT_CONNECTED) {
        /* 优先处理本地命令（不需要客户端在线的命令） */
        for (struct client_command_entry *c = get_client_commands(); c->name; c++) {
            if (strcmp(cmd, c->name) == 0) {
                /* exit 和 help 不需要检查客户端状态 */
                if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "help") == 0) {
                    return c->handler(client_fd, args ? args : "", session);
                }
                break;
            }
        }

        /* 对于需要客户端交互的命令，检查客户端状态 */
        client_info_t *client = NULL;
        int client_alive = 0;
        int client_socket_fd = -1;

        pthread_mutex_lock(&session->client_mgr->mutex);
        for (int i = 0; i < session->client_mgr->client_count; i++) {
            if (session->client_mgr->clients[i].client_id == session->current_client_id) {
                client = &session->client_mgr->clients[i];
                client_alive = client->is_alive;
                if (client_alive == 1) {
                    client_socket_fd = client->socket_fd;
                }
                break;
            }
        }
        pthread_mutex_unlock(&session->client_mgr->mutex);

        if (client && client_alive == 1) {
            /* 客户端仍然连接，更新 socket_fd */
            session->current_client_fd = client_socket_fd;
        } else if (client && client_alive == 0) {
            /* 客户端暂时断开，可能正在重连 */
            /* 等待时间: 客户端重连延迟5秒 + 网络延迟 + 缓冲 = 15秒总超时 */
            char output_buffer[1024];
            int offset = 0;

            offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset,
                             "Client %d temporarily disconnected, waiting for reconnection...\n",
                             session->current_client_id);

            for (int retry = 0; retry < 150; retry++) {
                usleep(100000);  // 等待 100ms，总共 15 秒

                /* 重新检查状态（需要加锁） */
                pthread_mutex_lock(&session->client_mgr->mutex);
                int reconnected = (client->is_alive == 1);
                if (reconnected) {
                    session->current_client_fd = client->socket_fd;
                }
                pthread_mutex_unlock(&session->client_mgr->mutex);

                if (reconnected) {
                    offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset,
                                     "Client %d reconnected successfully\n", session->current_client_id);
                    /* 添加提示符，一次性发送所有内容 */
                    offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset,
                                     "\001CLIENT_MODE:%d\001", session->current_client_id);
                    ssize_t written = write(client_fd, output_buffer, offset);
                    if (written < 0) {
                        perror("write failed in handle_command");
                    }
                    return 4;  /* 返回4表示已处理并已发送提示符 */
                }
            }

            /* 超时后仍未重连，退出会话 */
            pthread_mutex_lock(&session->client_mgr->mutex);
            int still_disconnected = (client->is_alive != 1);
            pthread_mutex_unlock(&session->client_mgr->mutex);

            if (still_disconnected) {
                offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset,
                                 "Client %d reconnection timeout (15s). Exiting session...\n\n",
                                 session->current_client_id);
                exit_client_session(session);
                /* 添加normal模式提示符 */
                offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset,
                                 "\001NORMAL_MODE\001");
                ssize_t written = write(client_fd, output_buffer, offset);
                if (written < 0) {
                    perror("write failed in handle_command");
                }
                return 4;  /* 返回4表示已处理并已发送提示符 */
            }
        }

        /* 客户端会话模式 - 处理客户端特定命令 */
        for (struct client_command_entry *c = get_client_commands(); c->name; c++) {
            if (strcmp(cmd, c->name) == 0) {
                return c->handler(client_fd, args ? args : "", session);
            }
        }

        dprintf(client_fd, "Unknown client command: %s\nType 'help' for client commands\n\n", cmd);
        return 0;
    } else {
        /* 正常管理模式 - 处理管理命令 */
        for (struct management_command_entry *c = get_management_commands(); c->name; c++) {
            if (strcmp(cmd, c->name) == 0) {
                return c->handler(client_fd, args ? args : "", session);
            }
        }

        dprintf(client_fd, "Unknown command: %s\nType 'help' for available commands\n\n", cmd);
        return 0;
    }
}
