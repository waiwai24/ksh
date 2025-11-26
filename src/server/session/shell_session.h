#ifndef SHELL_SESSION_H
#define SHELL_SESSION_H

#include "session_manager.h"

/* Shell模式处理函数 */
void handle_shell_mode(int client_fd, session_state_t *session);

#endif /* SHELL_SESSION_H */
