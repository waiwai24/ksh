#ifndef CORE_DAEMON_H
#define CORE_DAEMON_H

#include <signal.h>
#include <sys/types.h>
#include "../managers/client/client_manager.h"
#include "../managers/plugin/plugin_manager.h"

#define SOCKET_PATH "/tmp/daemon_terminal.sock"
#define PID_FILE "/tmp/daemon_terminal.pid"
#define INTERNAL_BUFFER_SIZE 16384

/* 控制台线程参数结构体 */
typedef struct {
    int client_fd;
    client_manager_t *client_mgr;
    plugin_manager_t *plugin_mgr;
} console_thread_args_t;

/* 守护进程相关函数 */
int create_daemon(void);
void daemon_loop(client_manager_t *client_mgr, plugin_manager_t *plugin_mgr);
int is_daemon_running(void);
void signal_handler(int sig);
void write_pid_file(pid_t pid);

/* 全局变量声明（供其他模块使用） */
extern int daemon_running;
extern int server_fd;
extern int network_fd;

#endif /* CORE_DAEMON_H */
