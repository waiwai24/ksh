#ifndef CLIENT_MANAGER_H
#define CLIENT_MANAGER_H

#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "../../crypto/protocol/pel.h"

#define MAX_CLIENTS 1000
#define MAX_IP_LEN 20
#define MAX_COUNTRY_LEN 8
#define MAX_HOSTNAME_LEN 64
#define MAX_OS_LEN 128

/* 客户端信息结构体 */
typedef struct {
    int client_id;                         // 客户端唯一编号
    int socket_fd;                         // 套接字描述符
    char ip_address[MAX_IP_LEN];           // IP地址
    char country[MAX_COUNTRY_LEN];         // 国家信息
    char hostname[MAX_HOSTNAME_LEN];       // 主机名
    char os[MAX_OS_LEN];                   // 操作系统信息
    time_t last_activity;                  // 最后活动时间
    int is_alive;                          // 是否存活 (0=断开, 1=连接)
    struct sockaddr_in client_addr;        // 客户端地址结构
    volatile int in_shell_mode;            // 是否正在shell模式（防止后台线程干扰）
    volatile int in_file_transfer;         // 是否正在文件传输（防止后台线程干扰）
    volatile int in_session;               // 是否有管理员正在会话中（防止多管理员并发冲突）

    /* PEL protocol context - per-client encryption state */
    struct pel_context send_ctx;           // 发送加密上下文
    struct pel_context recv_ctx;           // 接收解密上下文
    unsigned char pel_buffer[PEL_BUFFER_SIZE];  // PEL 加密缓冲区
} client_info_t;

/* 客户端管理器结构体 */
typedef struct {
    client_info_t clients[MAX_CLIENTS];    // 客户端数组
    int client_count;                      // 当前客户端数量（包括已断开的）
    int next_client_id;                    // 下一个可用的客户端ID
    pthread_mutex_t mutex;                 // 线程安全互斥锁
} client_manager_t;

extern client_manager_t g_client_manager;

int init_client_manager(client_manager_t *manager);
int add_client(client_manager_t *manager, int socket_fd, struct sockaddr_in *addr, const char *hostname);
int disconnect_client(client_manager_t *manager, int client_id);
int delete_client(client_manager_t *manager, int client_id);
int get_client_country(const char *ip_address, char *country_code, size_t code_len);
int update_client_activity(client_manager_t *manager, int client_id);
void cleanup_client_manager(client_manager_t *manager);

#endif /* CLIENT_MANAGER_H */