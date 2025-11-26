#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include "../managers/client/client_manager.h"
#include "../managers/plugin/plugin_manager.h"
#include "../../client/client.h"

/* 会话模式定义 */
typedef enum {
    SESSION_NORMAL = 0,            // 正常管理模式
    SESSION_CLIENT_CONNECTED = 1,  // 已连接到特定客户端
} session_mode_t;

/* 会话状态结构体 */
typedef struct {
    session_mode_t mode;              // 当前会话模式
    int current_client_id;            // 当前连接的客户端ID
    int current_client_fd;            // 当前客户端的socket fd
    client_manager_t *client_mgr;     // 客户端管理器引用
    plugin_manager_t *plugin_mgr;     // 插件管理器引用
    unsigned char message_buffer[FILE_BUFSIZE + 1];  // 会话独立缓冲区（避免多会话并发竞争）
} session_state_t;

void init_session_state(session_state_t *session, client_manager_t *client_mgr, plugin_manager_t *plugin_mgr);
int enter_client_session(session_state_t *session, int client_id);
int exit_client_session(session_state_t *session);

int handle_command(int client_fd, char *buffer, session_state_t *session);

#endif /* SESSION_MANAGER_H */
