#ifndef CLIENT_COMMANDS_H
#define CLIENT_COMMANDS_H

#include "../../session/session_manager.h"

/* 命令处理函数类型 */
typedef int (*client_command_handler_t)(int client_fd, const char *args, session_state_t *session);

/* 客户端命令表项结构 */
struct client_command_entry {
    const char *name;
    client_command_handler_t handler;
    const char *help;
};

/* 获取客户端命令表 */
struct client_command_entry* get_client_commands(void);

/* 客户端命令处理函数 */
int client_cmd_help(int client_fd, const char *args, session_state_t *session);
int client_cmd_get(int client_fd, const char *args, session_state_t *session);
int client_cmd_put(int client_fd, const char *args, session_state_t *session);
int client_cmd_shell(int client_fd, const char *args, session_state_t *session);
int client_cmd_clear(int client_fd, const char *args, session_state_t *session); /* Prototype for clear command */
int client_cmd_exit(int client_fd, const char *args, session_state_t *session);

#endif /* CLIENT_COMMANDS_H */
