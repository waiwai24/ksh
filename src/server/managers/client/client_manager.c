#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include "client_manager.h"

int init_client_manager(client_manager_t *manager) {
    if (!manager) return -1;

    memset(manager, 0, sizeof(client_manager_t));
    manager->client_count = 0;
    manager->next_client_id = 0;

    /* 初始化互斥锁 */
    if (pthread_mutex_init(&manager->mutex, NULL) != 0) {
        perror("Failed to initialize client_manager mutex");
        return -1;
    }

    return 0;
}

int add_client(client_manager_t *manager, int socket_fd, struct sockaddr_in *addr, const char *hostname) {
    if (!manager) {
        return -1;
    }

    pthread_mutex_lock(&manager->mutex);

    char ip_address[MAX_IP_LEN];
    if (addr) {
        inet_ntop(AF_INET, &addr->sin_addr, ip_address, MAX_IP_LEN - 1);
        ip_address[MAX_IP_LEN - 1] = '\0';
    } else {
        strcpy(ip_address, "Unknown");
    }

    /* 优先查找已删除的空槽位 (client_id == -1) */
    int free_slot = -1;
    for (int i = 0; i < manager->client_count; i++) {
        client_info_t *existing = &manager->clients[i];

        /* 找到空槽位，记录但继续查找更优的复用目标 */
        if (existing->client_id == -1) {
            if (free_slot == -1) {
                free_slot = i;
            }
            continue;
        }

        /* 检查是否有来自同一 IP 的已断开连接，优先复用 */
        if (existing->is_alive == 0 &&
            strcmp(existing->ip_address, ip_address) == 0) {

            if (hostname &&
                strcmp(existing->hostname, "Unknown") != 0 &&
                strcmp(existing->hostname, hostname) != 0) {
                /* IP相同但hostname不同，说明是NAT环境下的不同机器 */
                /* 不复用此槽位，继续查找 */
                continue;
            }

            /* 复用这个客户端槽位 */
            existing->socket_fd = socket_fd;
            existing->last_activity = time(NULL);
            existing->is_alive = 1;
            existing->in_shell_mode = 0;
            existing->in_file_transfer = 0;
            existing->in_session = 0;  // 重置会话占用标记

            /* 更新hostname和os为新连接的值 */
            if (hostname) {
                strncpy(existing->hostname, hostname, MAX_HOSTNAME_LEN - 1);
                existing->hostname[MAX_HOSTNAME_LEN - 1] = '\0';
            } else {
                strcpy(existing->hostname, "Unknown");
            }
            strcpy(existing->os, "Unknown");  // OS后续会更新

            if (addr) {
                existing->client_addr = *addr;
            }
            int client_id = existing->client_id;
            pthread_mutex_unlock(&manager->mutex);
            return client_id;
        }
    }

    /* 如果找到了空槽位，复用它 */
    client_info_t *client;
    if (free_slot != -1) {
        client = &manager->clients[free_slot];
    } else {
        /* 没有空槽位，检查是否还有空间创建新槽位 */
        if (manager->client_count >= MAX_CLIENTS) {
            pthread_mutex_unlock(&manager->mutex);
            return -1;
        }
        client = &manager->clients[manager->client_count];
        manager->client_count++;
    }

    client->client_id = manager->next_client_id++;
    client->socket_fd = socket_fd;
    client->last_activity = time(NULL);
    client->is_alive = 1;
    client->in_shell_mode = 0;
    client->in_file_transfer = 0;
    client->in_session = 0;
    if (addr) {
        client->client_addr = *addr;
        strcpy(client->ip_address, ip_address);

        if (get_client_country(ip_address, client->country, MAX_COUNTRY_LEN) != 0) {
            snprintf(client->country, MAX_COUNTRY_LEN, "Unknown");
        }
    } else {
        strcpy(client->ip_address, "Unknown");
        snprintf(client->country, MAX_COUNTRY_LEN, "Unknown");
    }

    if (hostname) {
        strncpy(client->hostname, hostname, MAX_HOSTNAME_LEN - 1);
        client->hostname[MAX_HOSTNAME_LEN - 1] = '\0';
    } else {
        strcpy(client->hostname, "Unknown");
    }
    strcpy(client->os, "Unknown");

    int client_id = client->client_id;
    pthread_mutex_unlock(&manager->mutex);
    return client_id;
}

int disconnect_client(client_manager_t *manager, int client_id) {
    if (!manager) return -1;

    pthread_mutex_lock(&manager->mutex);

    for (int i = 0; i < manager->client_count; i++) {
        if (manager->clients[i].client_id == client_id) {
            client_info_t *client = &manager->clients[i];

            // 关闭套接字但保留客户端信息
            if (client->socket_fd > 0) {
                close(client->socket_fd);
                client->socket_fd = -1;
            }

            client->is_alive = 0;
            client->last_activity = time(NULL);
            client->in_session = 0;
            pthread_mutex_unlock(&manager->mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&manager->mutex);
    return -1;
}

int delete_client(client_manager_t *manager, int client_id) {
    if (!manager) return -1;

    pthread_mutex_lock(&manager->mutex);

    for (int i = 0; i < manager->client_count; i++) {
        if (manager->clients[i].client_id == client_id) {
            client_info_t *client = &manager->clients[i];

            // 只允许删除已断开连接的客户端
            if (client->is_alive == 1) {
                pthread_mutex_unlock(&manager->mutex);
                return -2;  // 返回特殊错误码，表示客户端仍在连接中
            }

            if (client->socket_fd > 0) {
                close(client->socket_fd);
            }

            memset(client, 0, sizeof(client_info_t));
            client->client_id = -1;


            if (i == manager->client_count - 1) {
                while (manager->client_count > 0 &&
                       manager->clients[manager->client_count - 1].client_id == -1) {
                    manager->client_count--;
                }
            }

            pthread_mutex_unlock(&manager->mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&manager->mutex);
    return -1;
}

static int parse_country_code(const char *json_response, char *country_code, size_t code_len) {
    if (!json_response || !country_code || code_len < 3) {
        return -1;
    }

    const char *key = "\"countryCode\":\"";
    const char *pos = strstr(json_response, key);

    if (!pos) {
        return -1;
    }

    pos += strlen(key);

    int i = 0;
    while (i < (int)code_len - 1 && pos[i] != '"' && pos[i] != '\0') {
        country_code[i] = pos[i];
        i++;
    }
    country_code[i] = '\0';

    return (i > 0) ? 0 : -1;
}

int get_client_country(const char *ip_address, char *country_code, size_t code_len) {
    if (!ip_address || !country_code || code_len < 3) {
        return -1;
    }

    snprintf(country_code, code_len, "Unknown");

    if (strcmp(ip_address, "Unknown") == 0 || strcmp(ip_address, "127.0.0.1") == 0) {
        return -1;
    }

    int sockfd = -1;
    struct addrinfo hints, *servinfo = NULL;
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo("ip-api.com", "80", &hints, &servinfo)) != 0) {
        return -1;
    }

    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (sockfd == -1) {
        freeaddrinfo(servinfo);
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        close(sockfd);
        freeaddrinfo(servinfo);
        return -1;
    }

    freeaddrinfo(servinfo);

    char request[512];
    snprintf(request, sizeof(request),
             "GET /json/%s?fields=countryCode HTTP/1.1\r\n"
             "Host: ip-api.com\r\n"
             "Connection: close\r\n"
             "\r\n",
             ip_address);

    if (send(sockfd, request, strlen(request), 0) == -1) {
        close(sockfd);
        return -1;
    }

    char response[2048];
    memset(response, 0, sizeof(response));
    ssize_t total_received = 0;
    ssize_t bytes_received;

    while (total_received < (ssize_t)sizeof(response) - 1) {
        bytes_received = recv(sockfd, response + total_received,
                             sizeof(response) - total_received - 1, 0);
        if (bytes_received <= 0) {
            break;
        }
        total_received += bytes_received;
    }

    close(sockfd);

    if (total_received <= 0) {
        return -1;
    }

    response[total_received] = '\0';

    char *json_body = strstr(response, "\r\n\r\n");
    if (!json_body) {
        json_body = strstr(response, "\n\n");
    }

    if (!json_body) {
        return -1;
    }

    json_body += (json_body[1] == '\n') ? 2 : 4;

    return parse_country_code(json_body, country_code, code_len);
}

int update_client_activity(client_manager_t *manager, int client_id) {
    if (!manager) return -1;

    pthread_mutex_lock(&manager->mutex);

    for (int i = 0; i < manager->client_count; i++) {
        if (manager->clients[i].client_id == client_id) {
            manager->clients[i].last_activity = time(NULL);
            pthread_mutex_unlock(&manager->mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&manager->mutex);
    return -1;
}

void cleanup_client_manager(client_manager_t *manager) {
    if (!manager) return;

    pthread_mutex_lock(&manager->mutex);

    for (int i = 0; i < manager->client_count; i++) {
        if (manager->clients[i].socket_fd > 0) {
            close(manager->clients[i].socket_fd);
        }
    }

    manager->client_count = 0;

    pthread_mutex_unlock(&manager->mutex);

    /* 销毁互斥锁 */
    pthread_mutex_destroy(&manager->mutex);
}