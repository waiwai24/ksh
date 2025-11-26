#ifndef MANAGEMENT_COMMANDS_H
#define MANAGEMENT_COMMANDS_H

#include "../../session/session_manager.h"

/* 命令处理函数类型 */
typedef int (*command_handler_t)(int client_fd, const char *args, session_state_t *session);

/* 管理命令表项结构 */
struct management_command_entry {
    const char *name;
    command_handler_t handler;
    const char *help;
};

/* 获取管理命令表 */
struct management_command_entry* get_management_commands(void);

/* 管理命令处理函数 */
int cmd_help(int client_fd, const char *args, session_state_t *session);
int cmd_list(int client_fd, const char *args, session_state_t *session);
int cmd_delete(int client_fd, const char *args, session_state_t *session);
int cmd_entry(int client_fd, const char *args, session_state_t *session);
int cmd_command(int client_fd, const char *args, session_state_t *session);
int cmd_plugin(int client_fd, const char *args, session_state_t *session);
int cmd_quit(int client_fd, const char *args, session_state_t *session);
int cmd_disconnect(int client_fd, const char *args, session_state_t *session);

#endif /* MANAGEMENT_COMMANDS_H */
