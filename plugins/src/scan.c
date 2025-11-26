// gcc -o scan scan.c -pthread

#if defined(__FreeBSD__)
#define __BSD_VISIBLE 1
#endif

#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>


#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define _DEFAULT_SOURCE
#endif

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>

#include <sys/ioctl.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ifaddrs.h>

// 在包含平台特定头文件之前定义必要的宏
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
// 确保在BSD系统上正确定义所需类型
# ifndef u_char
#  define u_char unsigned char
# endif
# ifndef u_short
#  define u_short unsigned short
# endif
# ifndef u_int
#  define u_int unsigned int
# endif
# ifndef u_long
#  define u_long unsigned long
# endif
// 定义AF_MAX以支持net/if_var.h
# ifndef AF_MAX
#  define AF_MAX 42
# endif
#endif

#include <net/if.h> 

#ifndef IFF_UP
#define IFF_UP 0x1
#endif

#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 0x8
#endif

// 添加平台特定常量定义
#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

#if defined(__linux__)
    #include <netpacket/packet.h>
    #include <net/if_arp.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    #include <net/if_dl.h>
    #include <net/if_var.h>
    // 定义AF_LINK（如果未定义）
    #ifndef AF_LINK
    #define AF_LINK 18
    #endif
#endif

#define TIMEOUT_MS 150
#define MAX_SCAN_RANGE 254
#define MAX_THREADS 100
#define MAX_PORTS 128
#define MAX_IFACES 10

typedef struct {
    int port;
    const char *service;
} PortService;

/* 端口列表 */
static const PortService ports[] = {
    {20, "FTP-Data"},
    {21, "FTP"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {69, "TFTP"},
    {80, "HTTP"},
    {110, "POP3"},
    {111, "RPC"},
    {135, "MS-RPC"},
    {139, "NetBIOS"},
    {143, "IMAP"},
    {161, "SNMP"},
    {389, "LDAP"},
    {443, "HTTPS"},
    {445, "SMB"},
    {465, "SMTPS"},
    {587, "SMTP-Submit"},
    {993, "IMAPS"},
    {995, "POP3S"},
    {1080, "SOCKS"},
    {1433, "MSSQL"},
    {1521, "Oracle"},
    {2049, "NFS"},
    {2181, "Zookeeper"},
    {2375, "Docker"},
    {3000, "Node.js"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {4369, "Erlang"},
    {5000, "Flask"},
    {5432, "PostgreSQL"},
    {5672, "RabbitMQ"},
    {5900, "VNC"},
    {6379, "Redis"},
    {8000, "HTTP-Dev"},
    {8080, "HTTP-Proxy"},
    {8443, "HTTPS-Alt"},
    {8888, "HTTP-Alt2"},
    {9000, "PHP-FPM"},
    {9090, "Prometheus"},
    {9200, "Elasticsearch"},
    {9300, "ES-Transport"},
    {11211, "Memcached"},
    {27017, "MongoDB"},
    {50000, "SAP"},
    {50070, "Hadoop"}
};
static const int ports_count = sizeof(ports) / sizeof(ports[0]);

typedef struct {
    char name[16];
    char ip[16];
    char mac[18];
    char netmask[16];
    char network[16];
} NetworkInterface;

typedef struct {
    char ip[16];
    int is_alive;
    char hostname[256];
    char mac[18];
    char mac_vendor[64];
    int open_ports[MAX_PORTS];
    int port_count;
    long response_time_ms;
    char os_type[32];
    char device_type[64];
    char banner[256];
} ScanTask;

typedef struct {
    int verbose;
    int show_offline;
    int resolve_hostname;
    int detect_os;
} ScanConfig;

typedef struct {
    int total_scanned;
    int alive_hosts;
    int total_ports;
    time_t start_time;
    time_t end_time;
} ScanStats;

static pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static ScanConfig config = {0, 0, 1, 1};
static ScanStats stats = {0, 0, 0, 0, 0};

/* 获取毫秒时间戳（使用 64-bit 以防溢出） */
static long long get_time_ms_ll(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
}

/* 设置非阻塞 */
static int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

/* 非阻塞 connect 检测端口是否开放。返回 1=open, 0=closed */
int check_port(const char *ip, int port, long *response_time_ms) {
    int sockfd = -1;
    struct sockaddr_in addr;
    fd_set wfds;
    struct timeval tv;
    long long start = get_time_ms_ll();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (set_nonblocking(sockfd) != 0) {
        close(sockfd);
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(sockfd);
        return 0;
    }

    int ret = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret == 0) {
        if (response_time_ms) *response_time_ms = (long)(get_time_ms_ll() - start);
        close(sockfd);
        return 1;
    } else if (ret < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return 0;
    }

    FD_ZERO(&wfds);
    FD_SET(sockfd, &wfds);
    tv.tv_sec = TIMEOUT_MS / 1000;
    tv.tv_usec = (TIMEOUT_MS % 1000) * 1000;

    int sret = select(sockfd + 1, NULL, &wfds, NULL, &tv);
    if (sret > 0 && FD_ISSET(sockfd, &wfds)) {
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0) {
            if (so_error == 0) {
                if (response_time_ms) *response_time_ms = (long)(get_time_ms_ll() - start);
                close(sockfd);
                return 1;
            }
        }
    }

    close(sockfd);
    return 0;
}

/* 获取服务 Banner（尽量只读少量数据） */
int get_service_banner(const char *ip, int port, char *banner, size_t len) {
    int sockfd = -1;
    struct sockaddr_in addr;
    fd_set wfds, rfds;
    struct timeval tv;
    char buffer[512];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;

    if (set_nonblocking(sockfd) != 0) {
        close(sockfd);
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(sockfd);
        return 0;
    }

    int ret = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return 0;
    }

    /* 等待可写(连接完成) */
    FD_ZERO(&wfds);
    FD_SET(sockfd, &wfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (select(sockfd + 1, NULL, &wfds, NULL, &tv) <= 0) {
        close(sockfd);
        return 0;
    }

    /* 对于常见 HTTP 端口，发送简单请求 */
    if (port == 80 || port == 8080 || port == 8000 || port == 3000) {
        char req[256];
        snprintf(req, sizeof(req), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", ip);
        send(sockfd, req, strlen(req), 0);
    }
    /* 否则尝试读取被动 banner（例如 SSH/FTP） */

    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (select(sockfd + 1, &rfds, NULL, NULL, &tv) > 0 && FD_ISSET(sockfd, &rfds)) {
        ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            /* 只保留第一行并清理 CR/LF */
            char *newline = strchr(buffer, '\n');
            if (newline) *newline = '\0';
            char *cr = strchr(buffer, '\r');
            if (cr) *cr = '\0';
            strncpy(banner, buffer, len - 1);
            banner[len - 1] = '\0';
            close(sockfd);
            return 1;
        }
    }

    close(sockfd);
    return 0;
}

/* 读取 MAC 地址，优先使用系统工具，避免不必要的 ping */
void get_remote_mac(const char *ip, char *mac_out) {
    mac_out[0] = '\0';
    
#if defined(__linux__)
    // 1. 尝试直接读取 /proc/net/arp
    FILE *f = fopen("/proc/net/arp", "r");
    if (f) {
        char line[256];
        // 跳过表头
        if (fgets(line, sizeof(line), f) == NULL) {
            fclose(f);
            goto linux_fallback;
        }
        while (fgets(line, sizeof(line), f)) {
            char ipbuf[64], hwtype[16], flags[8], mac[32], mask[32], device[32];
            if (sscanf(line, "%63s %15s %7s %31s %31s %31s",
                       ipbuf, hwtype, flags, mac, mask, device) >= 4) {
                if (strcmp(ipbuf, ip) == 0 && strlen(mac) >= 11) {
                    strncpy(mac_out, mac, 17);
                    mac_out[17] = '\0';
                    fclose(f);
                    return;
                }
            }
        }
        fclose(f);
    }

linux_fallback:
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s > /dev/null 2>&1", ip);
    int sys_ret = system(cmd);
    (void)sys_ret;

    snprintf(cmd, sizeof(cmd), "ip neigh show %s 2>/dev/null | awk '{print $5}'", ip);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return;
    }
    char line[128];
    char *full_output = NULL;
    size_t output_size = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        char *new_output = realloc(full_output, output_size + len + 1);
        if (new_output == NULL) {
            perror("realloc failed");
            free(full_output);
            pclose(fp);
            return;
        }
        full_output = new_output;
        memcpy(full_output + output_size, line, len);
        output_size += len;
    }

    if (full_output != NULL) {
        full_output[output_size] = '\0';
        char *mac_ptr = NULL;

        if ((mac_ptr = strstr(full_output, ":"))) { // Simple check for presence of ':'
            // Attempt to extract MAC address from the line containing the IP
            // This part might need refinement based on exact output of 'ip neigh' or 'arp -n'
            // For simplicity, we'll assume the MAC is present and extract it.
            // A more robust solution would parse the line more carefully.
            
            // Example: Extracting the MAC from a line like "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
            // Or "192.168.1.1       00:11:22:33:44:55     0x6       *        eth0"
            
            // Let's try to find the MAC pattern directly in the output
            char *current_mac_ptr = full_output;
            while ((current_mac_ptr = strstr(current_mac_ptr, ":")) != NULL) {
                // Check if the surrounding characters form a valid MAC pattern
                // This is a heuristic and might need adjustment
                if (current_mac_ptr - full_output >= 17) { // Check if there's enough space before
                    char potential_mac[18];
                    strncpy(potential_mac, current_mac_ptr - 17, 17);
                    potential_mac[17] = '\0';
                    // Basic validation: check for hex chars and colons
                    int valid_chars = 1;
                    for(int i=0; i<17; ++i) {
                        if (i % 3 == 2) { // Expecting ':' at positions 2, 5, 8, 11, 14
                            if (potential_mac[i] != ':') { valid_chars = 0; break; }
                        } else { // Expecting hex characters
                            if (!isxdigit((unsigned char)potential_mac[i])) { valid_chars = 0; break; }
                        }
                    }
                    if (valid_chars) {
                        strncpy(mac_out, potential_mac, 17);
                        mac_out[17] = '\0';
                        break; // Found a potential MAC, exit loop
                    }
                }
                current_mac_ptr++; // Move to next character to continue search
            }
        }
        free(full_output);
    }
    pclose(fp);

#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    // On BSD systems, use 'arp -n'
    char cmd[256];
    // Trigger ARP by pinging. This ensures the entry is in the ARP table.
    // Using a short timeout.
    snprintf(cmd, sizeof(cmd), "ping -c 1 -t 1 %s > /dev/null 2>&1", ip);
    system(cmd);

    // Query the ARP table for the MAC address
    snprintf(cmd, sizeof(cmd), "arp -n %s 2>/dev/null | grep -o -E '([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}'", ip);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        // perror("popen arp"); // Optional: log error
        return; // Failed to open pipe
    }
    char line[128];
    if (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0'; // Remove trailing newline
        if (strlen(line) >= 11) { // Basic check for valid MAC format
            strncpy(mac_out, line, 17);
            mac_out[17] = '\0'; // Ensure null termination
        }
    }
    pclose(fp);
#elif defined(__CYGWIN__) || defined(_WIN32)
    /* Windows/Cygwin: use ping -n and parse arp -a output (MAC uses '-') */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -n 1 -w 1000 %s > /dev/null 2>&1", ip);
    system(cmd);

    FILE *fp = popen("arp -a", "r");
    if (!fp) {
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char ipbuf[64], macbuf[64];

        if (sscanf(line, " %63s %63s", ipbuf, macbuf) < 2) {
            continue;
        }

        if (strcmp(ipbuf, ip) != 0) {
            continue;
        }

        if (strlen(macbuf) != 17) {
            continue;
        }

        for (int i = 0; i < 17; ++i) {
            if (macbuf[i] == '-') {
                macbuf[i] = ':';
            } else {
                macbuf[i] = (char)toupper((unsigned char)macbuf[i]);
            }
        }

        strncpy(mac_out, macbuf, 17);
        mac_out[17] = '\0';
        break;
    }

    pclose(fp);
#else
    /* Other platforms: Use a generic approach (ping + arp -a) */
    char cmd[256];
    // Trigger ARP by pinging.
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s > /dev/null 2>&1", ip);
    system(cmd);

    // Query ARP table. 'arp -a' might vary in output format.
    // This grep pattern is common for MAC addresses.
    snprintf(cmd, sizeof(cmd), "arp -a | grep %s | grep -o -E '([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}'", ip);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        // perror("popen arp -a"); // Optional: log error
        return; // Failed to open pipe
    }
    char line[128];
    if (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0'; // Remove trailing newline
        if (strlen(line) >= 11) { // Basic check for valid MAC format
            strncpy(mac_out, line, 17);
            mac_out[17] = '\0'; // Ensure null termination
        }
    }
    pclose(fp);
#endif
}

/* 计算主机数量（根据 netmask），返回不超过 MAX_SCAN_RANGE */
int calculate_host_count(const char *netmask) {
    struct in_addr mask_addr;
    if (inet_pton(AF_INET, netmask, &mask_addr) != 1) return MAX_SCAN_RANGE;
    unsigned int mask = ntohl(mask_addr.s_addr);

    /* 计算 32 - count_ones(mask) */
    int ones = 0;
    for (int i = 31; i >= 0; --i) {
        if (mask & (1u << i)) ones++;
    }
    int host_bits = 32 - ones;
    if (host_bits <= 0) return 0;
    long hosts = (1L << host_bits) - 2;
    if (hosts < 0) hosts = 0;
    if (hosts > MAX_SCAN_RANGE) hosts = MAX_SCAN_RANGE;
    return (int)hosts;
}

/* 判断私有网段 */
int is_private_ip(const char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return 0;
    uint32_t ip_int = ntohl(addr.s_addr);
    if ((ip_int & 0xFF000000) == 0x0A000000) return 1;       /* 10.0.0.0/8 */
    if ((ip_int & 0xFFF00000) == 0xAC100000) return 1;       /* 172.16.0.0/12 */
    if ((ip_int & 0xFFFF0000) == 0xC0A80000) return 1;       /* 192.168.0.0/16 */
    if ((ip_int & 0xFFFF0000) == 0xA9FE0000) return 1;       /* 169.254.0.0/16 (link local) */
    return 0;
}

/* 计算网络地址（ip & mask），输出 dotted string */
void calculate_network(const char *ip, const char *netmask, char *network) {
    struct in_addr ip_a, mask_a, net_a;
    if (inet_pton(AF_INET, ip, &ip_a) != 1 || inet_pton(AF_INET, netmask, &mask_a) != 1) {
        strcpy(network, "0.0.0.0");
        return;
    }
    net_a.s_addr = ip_a.s_addr & mask_a.s_addr;
    inet_ntop(AF_INET, &net_a, network, INET_ADDRSTRLEN);
}

/* MAC地址OUI厂商数据库（前24位标识厂商）*/
typedef struct {
    const char *prefix;  /* MAC前缀（支持xx:xx:xx或xxxxxx格式）*/
    const char *vendor;  /* 厂商名称 */
    const char *type;    /* 设备类型提示 */
} MacVendor;

static const MacVendor mac_vendor_db[] = {
    /* ========== 虚拟机 ========== */
    {"00:50:56", "VMware", "虚拟机"},
    {"00:0C:29", "VMware", "虚拟机"},
    {"00:05:69", "VMware", "虚拟机"},
    {"00:1C:14", "VMware", "虚拟机"},
    {"08:00:27", "VirtualBox", "虚拟机"},
    {"52:54:00", "QEMU/KVM", "虚拟机"},
    {"00:15:5D", "Hyper-V", "虚拟机"},
    {"00:16:3E", "Xen", "虚拟机"},

    /* ========== 网络设备 ========== */
    /* Cisco思科 */
    {"00:00:0C", "Cisco思科", "网络设备"},
    {"00:01:42", "Cisco思科", "网络设备"},
    {"00:01:64", "Cisco思科", "网络设备"},
    {"00:06:28", "Cisco思科", "网络设备"},
    {"00:0B:85", "Cisco思科", "网络设备"},
    {"00:0B:BE", "Cisco思科", "网络设备"},
    {"00:0B:FC", "Cisco思科", "网络设备"},
    {"00:1B:D5", "Cisco思科", "网络设备"},
    {"F0:29:29", "Cisco思科", "网络设备"},
    {"6C:03:B5", "Cisco思科", "网络设备"},
    {"90:88:55", "Cisco思科", "网络设备"},
    {"68:71:61", "Cisco思科", "网络设备"},
    {"4C:EC:0F", "Cisco思科", "网络设备"},

    /* 华为Huawei */
    {"00:E0:FC", "华为Huawei", "网络设备"},
    {"00:25:9E", "华为Huawei", "网络设备"},
    {"00:1E:10", "华为Huawei", "网络设备"},
    {"00:25:68", "华为Huawei", "网络设备"},
    {"00:2E:C7", "华为Huawei", "网络设备"},
    {"10:86:F4", "华为Huawei", "网络设备"},
    {"28:45:AC", "华为Huawei", "网络设备"},
    {"4C:2B:3B", "华为Huawei", "网络设备"},
    {"58:B1:8F", "华为Huawei", "网络设备"},
    {"60:B0:E8", "华为Huawei", "网络设备"},
    {"88:15:66", "华为Huawei", "网络设备"},
    {"A4:43:80", "华为Huawei", "网络设备"},
    {"A8:09:B1", "华为Huawei", "网络设备"},
    {"B8:3C:20", "华为Huawei", "网络设备"},
    {"C8:91:0D", "华为Huawei", "网络设备"},
    {"E4:B1:07", "华为Huawei", "网络设备"},
    {"E0:06:30", "华为Huawei", "网络设备"},
    {"D8:DA:F1", "华为Huawei", "网络设备"},
    {"54:44:3B", "华为Huawei", "网络设备"},
    {"5C:70:75", "华为Huawei", "网络设备"},
    {"78:2D:AD", "华为Huawei", "网络设备"},
    {"D0:61:58", "华为Huawei", "网络设备"},
    {"24:4B:F1", "华为Huawei", "网络设备"},
    {"F0:A0:B1", "华为Huawei", "网络设备"},
    {"40:4F:42", "华为Huawei", "网络设备"},

    /* H3C新华三 */
    {"00:1E:EC", "H3C新华三", "网络设备"},
    {"00:25:B3", "H3C新华三", "网络设备"},
    {"F4:EA:67", "H3C新华三", "网络设备"},
    {"04:A9:59", "H3C新华三", "网络设备"},
    {"70:81:85", "H3C新华三", "网络设备"},

    /* Juniper瞻博网络 */
    {"00:03:0F", "Juniper瞻博", "网络设备"},
    {"00:05:85", "Juniper瞻博", "网络设备"},
    {"E4:F2:7C", "Juniper瞻博", "网络设备"},
    {"60:C7:8D", "Juniper瞻博", "网络设备"},
    {"3C:08:CD", "Juniper瞻博", "网络设备"},

    /* 锐捷Ruijie */
    {"00:0F:E2", "Ruijie锐捷", "网络设备"},
    {"00:24:A8", "Ruijie锐捷", "网络设备"},
    {"28:D0:F5", "Ruijie锐捷", "网络设备"},

    /* Ubiquiti网络设备 */
    {"00:27:22", "Ubiquiti", "网关设备"},
    {"04:18:D6", "Ubiquiti", "网关设备"},
    {"18:E8:29", "Ubiquiti", "网关设备"},
    {"24:5A:4C", "Ubiquiti", "网关设备"},
    {"24:A4:3C", "Ubiquiti", "网关设备"},
    {"44:D9:E7", "Ubiquiti", "网关设备"},
    {"68:72:51", "Ubiquiti", "网关设备"},
    {"68:D7:9A", "Ubiquiti", "网关设备"},
    {"70:A7:41", "Ubiquiti", "网关设备"},
    {"74:83:C2", "Ubiquiti", "网关设备"},
    {"74:AC:B9", "Ubiquiti", "网关设备"},
    {"78:8A:20", "Ubiquiti", "网关设备"},
    {"80:2A:A8", "Ubiquiti", "网关设备"},
    {"B4:FB:E4", "Ubiquiti", "网关设备"},
    {"DC:9F:DB", "Ubiquiti", "网关设备"},
    {"F0:9F:C2", "Ubiquiti", "网关设备"},
    {"FC:EC:DA", "Ubiquiti", "网关设备"},
    {"78:45:58", "Ubiquiti", "网关设备"},
    {"AC:8B:A9", "Ubiquiti", "网关设备"},
    {"9C:05:D6", "Ubiquiti", "网关设备"},
    {"0C:EA:14", "Ubiquiti", "网关设备"},

    /* TP-Link路由器/网关 */
    {"14:EB:B6", "TP-Link", "网关设备"},
    {"50:C7:BF", "TP-Link", "网关设备"},
    {"A0:F3:C1", "TP-Link", "网关设备"},
    {"68:DD:B7", "TP-Link", "网关设备"},
    {"14:D8:64", "TP-Link", "网关设备"},

    /* NETGEAR网关设备 */
    {"9C:C9:EB", "NETGEAR", "网关设备"},
    {"38:94:ED", "NETGEAR", "网关设备"},
    {"10:0C:6B", "NETGEAR", "网关设备"},
    {"78:D2:94", "NETGEAR", "网关设备"},
    {"B0:7F:B9", "NETGEAR", "网关设备"},
    {"40:5D:82", "NETGEAR", "网关设备"},
    {"DC:EF:09", "NETGEAR", "网关设备"},
    {"4C:60:DE", "NETGEAR", "网关设备"},
    {"C4:3D:C7", "NETGEAR", "网关设备"},
    {"08:BD:43", "NETGEAR", "网关设备"},
    {"28:94:01", "NETGEAR", "网关设备"},

    /* ZTE中兴 */
    {"00:19:C6", "ZTE中兴", "网络设备"},
    {"00:1E:73", "ZTE中兴", "网络设备"},
    {"08:F6:06", "ZTE中兴", "网络设备"},
    {"EC:F0:FE", "ZTE中兴", "网络设备"},
    {"F0:1B:24", "ZTE中兴", "网络设备"},
    {"98:EE:8C", "ZTE中兴", "网络设备"},
    {"90:C7:10", "ZTE中兴", "网络设备"},
    {"DC:51:93", "ZTE中兴", "网络设备"},
    {"F4:2E:48", "ZTE中兴", "网络设备"},
    {"20:3A:EB", "ZTE中兴", "网络设备"},
    {"88:7B:2C", "ZTE中兴", "网络设备"},
    {"68:9E:29", "ZTE中兴", "网络设备"},
    {"F4:3A:7B", "ZTE中兴", "网络设备"},
    {"C4:EB:FF", "ZTE中兴", "网络设备"},

    /* Aruba Networks (HP) */
    {"00:0B:86", "Aruba/HP", "网络设备"},
    {"00:1A:1E", "Aruba/HP", "网络设备"},
    {"6C:F3:7F", "Aruba/HP", "网络设备"},

    /* Fortinet防火墙 */
    {"00:09:0F", "Fortinet防火墙", "防火墙设备"},
    {"90:6C:AC", "Fortinet防火墙", "防火墙设备"},
    {"74:78:A6", "Fortinet防火墙", "防火墙设备"},
    {"84:39:8F", "Fortinet防火墙", "防火墙设备"},
    {"78:18:EC", "Fortinet防火墙", "防火墙设备"},

    /* Palo Alto Networks防火墙 */
    {"00:1B:17", "Palo Alto防火墙", "防火墙设备"},
    {"60:15:2B", "Palo Alto防火墙", "防火墙设备"},
    {"00:86:9C", "Palo Alto防火墙", "防火墙设备"},
    {"08:30:6B", "Palo Alto防火墙", "防火墙设备"},
    {"D4:F4:BE", "Palo Alto防火墙", "防火墙设备"},
    {"7C:C7:90", "Palo Alto防火墙", "防火墙设备"},

    /* SonicWall防火墙 */
    {"2C:B8:ED", "SonicWall防火墙", "防火墙设备"},
    {"00:06:B1", "SonicWall防火墙", "防火墙设备"},

    /* WatchGuard防火墙 */
    {"00:01:21", "WatchGuard防火墙", "防火墙设备"},

    /* Checkpoint防火墙 */
    {"00:17:8D", "Checkpoint防火墙", "防火墙设备"},

    /* Sophos防火墙 */
    {"A8:91:62", "Sophos防火墙", "防火墙设备"},

    /* Barracuda防火墙 */
    {"00:03:00", "Barracuda防火墙", "防火墙设备"},

    /* Stormshield防火墙 */
    {"00:0D:B4", "Stormshield防火墙", "防火墙设备"},

    /* 山石网科Hillstone防火墙 */
    {"30:29:52", "山石网科Hillstone", "防火墙设备"},

    /* 启明星辰Venustech */
    {"04:46:CF", "启明星辰Venustech", "防火墙设备"},

    /* SonicWall防火墙扩展 */
    {"18:C2:41", "SonicWall防火墙", "防火墙设备"},
    {"18:B1:69", "SonicWall防火墙", "防火墙设备"},
    {"C0:EA:E4", "SonicWall防火墙", "防火墙设备"},
    {"00:17:C5", "SonicWall防火墙", "防火墙设备"},
    {"FC:39:5A", "SonicWall防火墙", "防火墙设备"},

    /* MikroTik路由器 */
    {"00:0C:42", "MikroTik", "网关设备"},
    {"4C:5E:0C", "MikroTik", "网关设备"},
    {"B8:69:F4", "MikroTik", "网关设备"},
    {"78:9A:18", "MikroTik", "网关设备"},
    {"F4:1E:57", "MikroTik", "网关设备"},

    /* Arista Networks */
    {"FC:59:C0", "Arista Networks", "网络设备"},

    /* Edgecore Networks */
    {"D0:77:CE", "Edgecore Networks", "网络设备"},
    {"90:2D:77", "Edgecore Networks", "网络设备"},

    /* Extreme Networks */
    {"08:EA:44", "Extreme Networks", "网络设备"},
    {"F4:EA:B5", "Extreme Networks", "网络设备"},

    /* Intel服务器网卡 */
    {"00:02:B3", "Intel英特尔", "服务器"},
    {"00:07:E9", "Intel英特尔", "服务器"},
    {"00:1B:21", "Intel英特尔", "服务器"},
    {"00:1E:67", "Intel英特尔", "服务器"},
    {"A0:36:9F", "Intel英特尔", "服务器"},
    {"A0:02:A5", "Intel英特尔", "服务器"},
    {"E4:C7:67", "Intel英特尔", "服务器"},

    /* Dell戴尔服务器 */
    {"00:06:5B", "Dell戴尔", "服务器"},
    {"00:0B:DB", "Dell戴尔", "服务器"},
    {"00:14:5E", "Dell戴尔", "服务器"},
    {"00:1A:A0", "Dell戴尔", "服务器"},
    {"00:1E:C9", "Dell戴尔", "服务器"},
    {"D4:AE:52", "Dell戴尔", "服务器"},
    {"D0:43:1E", "Dell戴尔", "服务器"},

    /* HP惠普服务器 */
    {"00:01:E6", "HP惠普", "服务器"},
    {"00:01:E7", "HP惠普", "服务器"},
    {"00:02:A5", "HP惠普", "服务器"},
    {"00:0B:CD", "HP惠普", "服务器"},
    {"00:15:C5", "HP惠普", "服务器"},
    {"00:17:A4", "HP惠普", "服务器"},
    {"3C:A8:2A", "HP惠普", "服务器"},
    {"64:4E:D7", "HP惠普", "服务器"},

    /* IBM服务器 */
    {"00:09:6B", "IBM", "服务器"},
    {"08:00:5A", "IBM", "服务器"},

    /* Lenovo联想 */
    {"00:1A:4B", "Lenovo联想", "服务器"},
    {"00:21:CC", "Lenovo联想", "服务器"},

    /* Microsoft */
    {"00:03:FF", "Microsoft", "服务器"},

    /* 小米IoT设备 */
    {"34:CE:00", "小米Xiaomi", "IoT设备"},
    {"78:11:DC", "小米Xiaomi", "IoT设备"},
    {"AC:23:3F", "小米Xiaomi", "IoT设备"},
    {"CC:D8:43", "小米Xiaomi", "IoT设备"},
    {"F4:8E:38", "小米Xiaomi", "IoT设备"},
    {"CC:EB:5E", "小米Xiaomi", "IoT设备"},
    {"B8:EA:98", "小米Xiaomi", "IoT设备"},
    {"8C:D0:B2", "小米Xiaomi", "IoT设备"},
    {"F4:1A:9C", "小米Xiaomi", "IoT设备"},
    {"DC:6A:E7", "小米Xiaomi", "IoT设备"},
    {"7C:A4:49", "小米Xiaomi", "IoT设备"},
    {"C8:BF:4C", "小米Xiaomi", "IoT设备"},

    /* Amazon IoT设备 */
    {"44:65:0D", "Amazon Echo/IoT", "IoT设备"},
    {"F0:D2:F1", "Amazon Echo/IoT", "IoT设备"},
    {"84:28:59", "Amazon Echo/IoT", "IoT设备"},
    {"28:73:F6", "Amazon Echo/IoT", "IoT设备"},
    {"E0:CB:1D", "Amazon Echo/IoT", "IoT设备"},
    {"FC:D7:49", "Amazon Echo/IoT", "IoT设备"},
    {"08:91:A3", "Amazon Echo/IoT", "IoT设备"},
    {"6C:0C:9A", "Amazon Echo/IoT", "IoT设备"},
    {"08:91:15", "Amazon Echo/IoT", "IoT设备"},
    {"74:D4:23", "Amazon Echo/IoT", "IoT设备"},
    {"EC:A1:38", "Amazon Echo/IoT", "IoT设备"},

    /* Google Nest/IoT设备 */
    {"3C:5A:B4", "Google Nest", "IoT设备"},
    {"54:60:09", "Google Nest", "IoT设备"},
    {"60:70:6C", "Google Nest", "IoT设备"},
    {"C8:2A:DD", "Google Nest", "IoT设备"},

    /* Tuya智能家居 */
    {"1C:90:FF", "Tuya Smart", "IoT设备"},

    /* Broadlink智能家居 */
    {"E8:70:72", "Broadlink", "IoT设备"},
    {"24:DF:A7", "Broadlink", "IoT设备"},
    {"34:8E:89", "Broadlink", "IoT设备"},

    /* Espressif (ESP32/ESP8266 IoT芯片) */
    {"10:06:1C", "Espressif IoT", "IoT设备"},
    {"D4:8A:FC", "Espressif IoT", "IoT设备"},
    {"E4:65:B8", "Espressif IoT", "IoT设备"},

    /* 海康威视监控 */
    {"44:19:B6", "海康威视", "监控摄像头"},
    {"BC:AD:28", "海康威视", "监控摄像头"},
    {"F0:B4:29", "海康威视", "监控摄像头"},
    {"0C:75:D2", "海康威视", "监控摄像头"},
    {"54:8C:81", "海康威视", "监控摄像头"},
    {"24:48:45", "海康威视", "监控摄像头"},
    {"EC:C8:9C", "海康威视", "监控摄像头"},
    {"8C:E7:48", "海康威视", "监控摄像头"},
    {"24:28:FD", "海康威视", "监控摄像头"},
    {"AC:B9:2F", "海康威视", "监控摄像头"},
    {"D4:E8:53", "海康威视", "监控摄像头"},
    {"24:0F:9B", "海康威视", "监控摄像头"},
    {"C0:6D:ED", "海康威视", "监控摄像头"},
    {"24:32:AE", "海康威视", "监控摄像头"},
    {"E0:BA:AD", "海康威视", "监控摄像头"},
    {"E0:CA:3C", "海康威视", "监控摄像头"},
    {"DC:07:F8", "海康威视", "监控摄像头"},
    {"64:DB:8B", "海康威视", "监控摄像头"},
    {"94:E1:AC", "海康威视", "监控摄像头"},
    {"58:03:FB", "海康威视", "监控摄像头"},
    {"44:47:CC", "海康威视", "监控摄像头"},
    {"98:DF:82", "海康威视", "监控摄像头"},
    {"C0:56:E3", "海康威视", "监控摄像头"},
    {"80:F5:AE", "海康威视", "监控摄像头"},

    /* 大华Dahua监控 */
    {"00:12:16", "大华Dahua", "监控摄像头"},
    {"1C:B7:2C", "大华Dahua", "监控摄像头"},
    {"74:C9:29", "大华Dahua", "监控摄像头"},
    {"6C:1C:71", "大华Dahua", "监控摄像头"},
    {"08:ED:ED", "大华Dahua", "监控摄像头"},

    /* Axis Communications监控 */
    {"B8:A4:4F", "Axis监控", "监控摄像头"},

    /* 打印机厂商 */
    {"00:00:48", "HP打印机", "打印机"},
    {"00:01:E6", "HP打印机", "打印机"},
    {"00:04:76", "Canon佳能", "打印机"},
    {"A8:1B:5A", "Canon佳能", "打印机"},
    {"00:00:85", "Epson爱普生", "打印机"},
    {"00:04:A8", "Brother兄弟", "打印机"},

    /* Apple设备 */
    {"00:03:93", "Apple苹果", "Mac/iPhone/iPad"},
    {"00:0A:27", "Apple苹果", "Mac/iPhone/iPad"},
    {"00:0A:95", "Apple苹果", "Mac/iPhone/iPad"},
    {"A4:D1:D2", "Apple苹果", "Mac/iPhone/iPad"},
    {"AC:87:A3", "Apple苹果", "Mac/iPhone/iPad"},
    {"F0:EE:7A", "Apple苹果", "Mac/iPhone/iPad"},
    {"58:AD:12", "Apple苹果", "Mac/iPhone/iPad"},
    {"60:FD:A6", "Apple苹果", "Mac/iPhone/iPad"},
    {"80:A9:97", "Apple苹果", "Mac/iPhone/iPad"},
    {"34:8C:5E", "Apple苹果", "Mac/iPhone/iPad"},
    {"20:15:82", "Apple苹果", "Mac/iPhone/iPad"},
    {"40:92:1A", "Apple苹果", "Mac/iPhone/iPad"},
    {"10:E2:C9", "Apple苹果", "Mac/iPhone/iPad"},

    /* Samsung三星 */
    {"00:12:FB", "Samsung三星", "移动设备"},
    {"00:16:32", "Samsung三星", "移动设备"},
    {"00:1A:8A", "Samsung三星", "移动设备"},
    {"34:23:BA", "Samsung三星", "移动设备"},
    {"38:AA:3C", "Samsung三星", "移动设备"},
    {"64:1B:2F", "Samsung三星", "移动设备"},
    {"9C:73:B1", "Samsung三星", "移动设备"},
    {"38:8A:06", "Samsung三星", "移动设备"},

    /* LG电子 */
    {"00:1C:62", "LG Electronics", "移动设备"},
    {"00:1E:75", "LG Electronics", "移动设备"},
    {"10:68:3F", "LG Electronics", "移动设备"},

    /* Sony索尼 */
    {"00:02:5B", "Sony索尼", "消费电子"},
    {"00:13:15", "Sony索尼", "消费电子"},
    {"AC:9B:0A", "Sony索尼", "消费电子"},

    /* ASUS华硕 */
    {"00:1F:C6", "ASUS华硕", "PC/笔记本"},
    {"04:D4:C4", "ASUS华硕", "PC/笔记本"},
    {"08:60:6E", "ASUS华硕", "PC/笔记本"},

    /* Acer宏碁 */
    {"00:03:0D", "Acer宏碁", "PC/笔记本"},
    {"00:0E:35", "Acer宏碁", "PC/笔记本"},

    /* MSI微星 */
    {"00:1D:72", "MSI微星", "PC/笔记本"},

    /* Gigabyte技嘉 */
    {"00:1B:38", "Gigabyte技嘉", "PC/主板"},

    /* 树莓派 */
    {"B8:27:EB", "树莓派Raspberry Pi", "嵌入式设备"},
    {"DC:A6:32", "树莓派Raspberry Pi", "嵌入式设备"},
    {"E4:5F:01", "树莓派Raspberry Pi", "嵌入式设备"},

    /* Realtek瑞昱网卡 */
    {"00:E0:4C", "Realtek瑞昱", "PC网卡"},

    /* Broadcom博通 */
    {"00:18:82", "Broadcom博通", "PC网卡"},
    {"00:26:B9", "Broadcom博通", "PC网卡"},

    /* Qualcomm高通 */
    {"00:03:7F", "Qualcomm高通", "移动芯片"},

    /* Nvidia英伟达 */
    {"00:04:4B", "Nvidia英伟达", "GPU/网卡"},

    /* AMD */
    {"00:00:1A", "AMD", "PC/网卡"},

    /* DrayTek路由器 */
    {"14:49:BC", "DrayTek", "网关设备"},
    {"00:1D:AA", "DrayTek", "网关设备"},
    {"00:50:7F", "DrayTek", "网关设备"},

    /* Zyxel网关设备 */
    {"F8:0D:A9", "Zyxel", "网关设备"},
    {"88:AC:C0", "Zyxel", "网关设备"},
    {"00:23:F8", "Zyxel", "网关设备"},
    {"00:19:CB", "Zyxel", "网关设备"},
    {"1C:74:0D", "Zyxel", "网关设备"},
    {"5C:F4:AB", "Zyxel", "网关设备"},
    {"28:28:5D", "Zyxel", "网关设备"},

    /* D-Link网关设备*/
    {"BC:22:28", "D-Link", "网关设备"},
    {"A0:A3:F0", "D-Link", "网关设备"},
    {"BC:0F:9A", "D-Link", "网关设备"},
    {"74:DA:DA", "D-Link", "网关设备"},
    {"10:62:EB", "D-Link", "网关设备"},
    {"1C:5F:2B", "D-Link", "网关设备"},
    {"00:50:BA", "D-Link", "网关设备"},
    {"00:17:9A", "D-Link", "网关设备"},
    {"00:1C:F0", "D-Link", "网关设备"},
    {"00:1E:58", "D-Link", "网关设备"},
    {"00:22:B0", "D-Link", "网关设备"},
    {"00:24:01", "D-Link", "网关设备"},
    {"1C:AF:F7", "D-Link", "网关设备"},
    {"14:D6:4D", "D-Link", "网关设备"},
    {"90:94:E4", "D-Link", "网关设备"},
    {"CC:B2:55", "D-Link", "网关设备"},
    {"28:10:7B", "D-Link", "网关设备"},
    {"FC:75:16", "D-Link", "网关设备"},
    {"84:C9:B2", "D-Link", "网关设备"},
    {"C8:D3:A3", "D-Link", "网关设备"},
    {"C4:12:F5", "D-Link", "网关设备"},
    {"B0:C5:54", "D-Link", "网关设备"},
    {"5C:D9:98", "D-Link", "网关设备"},

    /* Tenda腾达路由器 */
    {"B4:0F:3B", "Tenda腾达", "网关设备"},

    /* 水星Mercury路由器 */
    {"0C:96:CD", "Mercury水星", "网关设备"},
    {"48:8A:D2", "Mercury水星", "网关设备"},
    {"00:27:1C", "Mercury水星", "网关设备"},

    /* FAST迅捷路由器 */
    {"0C:D8:6C", "FAST迅捷", "网关设备"},

    /* TOTOLINK路由器 */
    {"84:68:C8", "TOTOLINK", "网关设备"},

    /* Cudy路由器 */
    {"80:AF:CA", "Cudy", "网关设备"},
    {"D4:0D:AB", "Cudy", "网关设备"},

    /* eero Mesh路由器 */
    {"08:F0:1E", "eero", "网关设备"},

    /* Linksys */
    {"00:1D:7E", "Linksys", "网关设备"},
    {"00:14:BF", "Linksys", "网关设备"},
    {"48:F8:B3", "Linksys", "网关设备"},
    {"C0:C1:C0", "Linksys", "网关设备"},

    /* Texas Instruments */
    {"40:F3:B0", "Texas Instruments", "IoT设备"},

    {NULL, NULL, NULL}  /* 结束标记 */
};

/* 查询MAC地址厂商 */
const char* lookup_mac_vendor(const char *mac, char *device_hint) {
    if (!mac || mac[0] == '\0') {
        if (device_hint) device_hint[0] = '\0';
        return "未知厂商";
    }

    /* 提取MAC前3字节（OUI）*/
    char oui[9];
    int mac_len = strlen(mac);

    /* 支持 "xx:xx:xx" 或 "xx-xx-xx" 格式 */
    if (mac_len >= 8) {
        /* 复制前8个字符 "xx:xx:xx" 并统一转大写 */
        for (int i = 0; i < 8; i++) {
            oui[i] = toupper((unsigned char)mac[i]);
        }
        oui[8] = '\0';
    } else {
        if (device_hint) device_hint[0] = '\0';
        return "未知厂商";
    }

    /* 查询数据库 */
    for (int i = 0; mac_vendor_db[i].prefix != NULL; i++) {
        if (strncmp(oui, mac_vendor_db[i].prefix, 8) == 0) {
            if (device_hint && mac_vendor_db[i].type) {
                strncpy(device_hint, mac_vendor_db[i].type, 63);
                device_hint[63] = '\0';
            }
            return mac_vendor_db[i].vendor;
        }
    }

    if (device_hint) device_hint[0] = '\0';
    return "未知厂商";
}

/* 获取本机网卡物理地址 */
void get_mac_address(const char *ifname, char *mac) {
    struct ifaddrs *ifaddr, *ifa;
    mac[0] = '\0';
    if (getifaddrs(&ifaddr) == -1) {
        strcpy(mac, "未知");
        return;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;
        
#if defined(__linux__)
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            if (s->sll_halen == 6) {
                snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                         s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                         s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
                freeifaddrs(ifaddr);
                return;
            }
        }
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *s = (struct sockaddr_dl*)ifa->ifa_addr;
            if (s->sdl_alen == 6) {
                unsigned char *mac_addr = (unsigned char*)LLADDR(s);
                snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac_addr[0], mac_addr[1], mac_addr[2],
                         mac_addr[3], mac_addr[4], mac_addr[5]);
                freeifaddrs(ifaddr);
                return;
            }
        }
#else
        // 其他平台的通用处理或错误处理
        strcpy(mac, "未知");
        freeifaddrs(ifaddr);
        return;
#endif
    }
    freeifaddrs(ifaddr);
    strcpy(mac, "未知");
}

/* 枚举并填充内网接口列表 */
int get_network_interfaces(NetworkInterface *interfaces, int max_count) {
    struct ifaddrs *ifaddr, *ifa;
    int count = 0;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }
    for (ifa = ifaddr; ifa != NULL && count < max_count; ifa = ifa->ifa_next) {
        // 合并多个条件检查以减少嵌套
        if (ifa->ifa_addr == NULL || 
            ifa->ifa_addr->sa_family != AF_INET || 
            (ifa->ifa_flags & IFF_LOOPBACK) || 
            !(ifa->ifa_flags & IFF_UP)) {
            continue;
        }

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;
        char ip_str[16];
        inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
        
        // 检查是否为私有IP
        if (!is_private_ip(ip_str)) continue;

        snprintf(interfaces[count].name, sizeof(interfaces[count].name), "%s", ifa->ifa_name);
        snprintf(interfaces[count].ip, sizeof(interfaces[count].ip), "%s", ip_str);
        inet_ntop(AF_INET, &netmask->sin_addr, interfaces[count].netmask, sizeof(interfaces[count].netmask));
        calculate_network(interfaces[count].ip, interfaces[count].netmask, interfaces[count].network);
        get_mac_address(ifa->ifa_name, interfaces[count].mac);
        count++;
    }
    freeifaddrs(ifaddr);
    return count;
}

/* 端口存在性快速查询（使用位图优化） */
typedef struct {
    uint64_t bitmap_low;   /* 端口 0-63 */
    uint64_t bitmap_mid;   /* 端口 64-127 */
    uint64_t bitmap_high[6]; /* 端口 128-511，每个uint64存储64个端口 */
} PortBitmap;

static inline void port_bitmap_set(PortBitmap *bm, int port) {
    if (port < 64) {
        bm->bitmap_low |= (1ULL << port);
    } else if (port < 128) {
        bm->bitmap_mid |= (1ULL << (port - 64));
    } else if (port < 512) {
        int idx = (port - 128) / 64;
        int bit = (port - 128) % 64;
        if (idx < 6) {
            bm->bitmap_high[idx] |= (1ULL << bit);
        }
    }
}

static inline int port_bitmap_has(const PortBitmap *bm, int port) {
    if (port < 64) {
        return (bm->bitmap_low & (1ULL << port)) != 0;
    } else if (port < 128) {
        return (bm->bitmap_mid & (1ULL << (port - 64))) != 0;
    } else if (port < 512) {
        int idx = (port - 128) / 64;
        int bit = (port - 128) % 64;
        if (idx < 6) {
            return (bm->bitmap_high[idx] & (1ULL << bit)) != 0;
        }
    }
    return 0;
}

/* 增强的 OS 指纹识别：基于端口组合、Banner和启发式规则 */
void detect_os_enhanced(ScanTask *task) {
    if (!config.detect_os) {
        task->os_type[0] = '\0';
        task->device_type[0] = '\0';
        return;
    }

    /* 构建端口位图，O(1)查询 */
    PortBitmap pb;
    memset(&pb, 0, sizeof(pb));
    for (int i = 0; i < task->port_count; i++) {
        port_bitmap_set(&pb, ports[task->open_ports[i]].port);
    }

    /* MAC厂商辅助信息（优先级最高） */
    char mac_device_hint[64];
    mac_device_hint[0] = '\0';
    if (task->mac[0] != '\0') {
        lookup_mac_vendor(task->mac, mac_device_hint);
    }

    /* MAC厂商预判断（提前识别特定设备） */
    if (mac_device_hint[0] != '\0') {
        /* 虚拟机识别 */
        if (strstr(mac_device_hint, "虚拟机")) {
            if (task->os_type[0] == '\0') strcpy(task->os_type, "虚拟化平台");
            /* 根据端口进一步细化虚拟机类型 */
            if (port_bitmap_has(&pb, 22)) {
                strcpy(task->device_type, "Linux虚拟机");
            } else if (port_bitmap_has(&pb, 3389)) {
                strcpy(task->device_type, "Windows虚拟机");
            } else {
                strcpy(task->device_type, task->mac_vendor);
            }
            return;  /* 虚拟机识别完成，直接返回 */
        }
        /* 摄像头识别 */
        else if (strstr(mac_device_hint, "摄像头") || strstr(task->mac_vendor, "海康") || strstr(task->mac_vendor, "大华")) {
            if (task->os_type[0] == '\0') strcpy(task->os_type, "嵌入式Linux");
            snprintf(task->device_type, sizeof(task->device_type), "%s", task->mac_vendor);
            return;  /* 摄像头识别完成 */
        }
        /* 打印机识别 */
        else if (strstr(mac_device_hint, "打印机")) {
            if (task->os_type[0] == '\0') strcpy(task->os_type, "嵌入式系统");
            snprintf(task->device_type, sizeof(task->device_type), "%s", task->mac_vendor);
            return;  /* 打印机识别完成 */
        }
        /* IoT设备识别 */
        else if (strstr(mac_device_hint, "IoT")) {
            if (task->os_type[0] == '\0') strcpy(task->os_type, "IoT系统");
            snprintf(task->device_type, sizeof(task->device_type), "%s", task->mac_vendor);
            return;  /* IoT设备识别完成 */
        }
        /* 树莓派识别 */
        else if (strstr(task->mac_vendor, "树莓派")) {
            if (task->os_type[0] == '\0') strcpy(task->os_type, "Linux/Raspbian");
            strcpy(task->device_type, "树莓派开发板");
            return;  /* 树莓派识别完成 */
        }
        /* Apple设备识别 */
        else if (strstr(task->mac_vendor, "Apple")) {
            if (task->os_type[0] == '\0') {
                /* 根据端口判断是Mac还是iOS */
                if (port_bitmap_has(&pb, 22) || port_bitmap_has(&pb, 548)) {
                    strcpy(task->os_type, "macOS");
                } else {
                    strcpy(task->os_type, "iOS/iPadOS");
                }
            }
            strcpy(task->device_type, "Apple设备");
            /* 可以继续后续端口分析细化 */
        }
    }

    /* Banner分析（优先级第二） */
    if (task->banner[0]) {
        /* 转换为小写以便匹配 */
        char banner_lower[256];
        for (size_t i = 0; i < sizeof(banner_lower) - 1 && task->banner[i]; i++) {
            banner_lower[i] = tolower((unsigned char)task->banner[i]);
        }
        banner_lower[strlen(task->banner)] = '\0';

        /* 根据Banner特征判断 */
        if (strstr(banner_lower, "ubuntu")) {
            strcpy(task->os_type, "Linux/Ubuntu");
        } else if (strstr(banner_lower, "centos") || strstr(banner_lower, "redhat") || strstr(banner_lower, "rhel")) {
            strcpy(task->os_type, "Linux/CentOS");
        } else if (strstr(banner_lower, "debian")) {
            strcpy(task->os_type, "Linux/Debian");
        } else if (strstr(banner_lower, "windows") || strstr(banner_lower, "microsoft")) {
            strcpy(task->os_type, "Windows");
        } else if (strstr(banner_lower, "freebsd")) {
            strcpy(task->os_type, "FreeBSD");
        } else if (strstr(banner_lower, "openbsd")) {
            strcpy(task->os_type, "OpenBSD");
        } else if (strstr(banner_lower, "nginx") || strstr(banner_lower, "apache")) {
            strcpy(task->os_type, "Linux");
        } else if (strstr(banner_lower, "ssh") && strstr(banner_lower, "openssh")) {
            strcpy(task->os_type, "Unix-like");
        }
    }

    /* 端口模式识别 */

    /* 1. Windows特征检测 */
    int is_windows = 0;
    if (port_bitmap_has(&pb, 3389) || /* RDP */
        (port_bitmap_has(&pb, 445) && port_bitmap_has(&pb, 135) && port_bitmap_has(&pb, 139)) || /* SMB+RPC+NetBIOS */
        (port_bitmap_has(&pb, 1433) && !port_bitmap_has(&pb, 22))) { /* MSSQL without SSH */
        is_windows = 1;
        if (task->os_type[0] == '\0') strcpy(task->os_type, "Windows");
    }

    /* 2. Linux/Unix特征检测 */
    int is_linux = port_bitmap_has(&pb, 22); /* SSH */

    /* 3. 网络设备特征 */
    int is_network_device = 0;
    /* MAC厂商辅助判断网络设备 */
    if (mac_device_hint[0] != '\0' && strstr(mac_device_hint, "网络设备")) {
        is_network_device = 1;
        if (task->os_type[0] == '\0') strcpy(task->os_type, "嵌入式系统");
    }
    /* 端口特征判断网络设备 */
    else if (port_bitmap_has(&pb, 23) && /* Telnet */
        (port_bitmap_has(&pb, 161) || port_bitmap_has(&pb, 80)) && /* SNMP or HTTP */
        !port_bitmap_has(&pb, 445) && !port_bitmap_has(&pb, 3389)) { /* 非Windows */
        is_network_device = 1;
        if (task->os_type[0] == '\0') strcpy(task->os_type, "嵌入式系统");
    }

    /* 4. 打印机特征 */
    if ((port_bitmap_has(&pb, 9100) || port_bitmap_has(&pb, 515) || port_bitmap_has(&pb, 631)) &&
        !port_bitmap_has(&pb, 22) && !port_bitmap_has(&pb, 3389)) {
        if (task->os_type[0] == '\0') strcpy(task->os_type, "嵌入式系统");
        strcpy(task->device_type, "网络打印机");
        return;
    }

    /* 设备类型详细分类 */
    if (is_windows) {
        /* Windows设备细分 */
        if (port_bitmap_has(&pb, 3389)) {
            strcpy(task->device_type, "Windows服务器/桌面");
        } else if (port_bitmap_has(&pb, 1433)) {
            strcpy(task->device_type, "Windows数据库服务器");
        } else {
            strcpy(task->device_type, "Windows主机");
        }
    } else if (is_network_device) {
        /* 网络设备细分（结合MAC厂商信息） */
        if (task->mac_vendor[0] != '\0' && strstr(mac_device_hint, "网络设备")) {
            /* 使用MAC厂商名称作为设备类型 */
            snprintf(task->device_type, sizeof(task->device_type), "%s", task->mac_vendor);
        } else if (port_bitmap_has(&pb, 161)) {
            strcpy(task->device_type, "网络设备(路由器/交换机)");
        } else {
            strcpy(task->device_type, "网络设备");
        }
    } else if (is_linux) {
        /* Linux设备细分 */
        if (task->os_type[0] == '\0') strcpy(task->os_type, "Linux");

        /* MAC厂商辅助识别服务器品牌 */
        int is_server_vendor = 0;
        if (mac_device_hint[0] != '\0' && strstr(mac_device_hint, "服务器")) {
            is_server_vendor = 1;
        }

        /* 数据库服务器 */
        if (port_bitmap_has(&pb, 3306) || port_bitmap_has(&pb, 5432) ||
            port_bitmap_has(&pb, 6379) || port_bitmap_has(&pb, 27017) ||
            port_bitmap_has(&pb, 1521) || port_bitmap_has(&pb, 11211)) {

            /* 添加服务器品牌信息 */
            if (is_server_vendor) {
                char temp_type[128];
                if (port_bitmap_has(&pb, 3306)) snprintf(temp_type, sizeof(temp_type), "MySQL数据库服务器[%s]", task->mac_vendor);
                else if (port_bitmap_has(&pb, 5432)) snprintf(temp_type, sizeof(temp_type), "PostgreSQL数据库服务器[%s]", task->mac_vendor);
                else if (port_bitmap_has(&pb, 6379)) snprintf(temp_type, sizeof(temp_type), "Redis缓存服务器[%s]", task->mac_vendor);
                else if (port_bitmap_has(&pb, 27017)) snprintf(temp_type, sizeof(temp_type), "MongoDB数据库服务器[%s]", task->mac_vendor);
                else if (port_bitmap_has(&pb, 1521)) snprintf(temp_type, sizeof(temp_type), "Oracle数据库服务器[%s]", task->mac_vendor);
                else snprintf(temp_type, sizeof(temp_type), "数据库服务器[%s]", task->mac_vendor);
                strncpy(task->device_type, temp_type, sizeof(task->device_type) - 1);
                task->device_type[sizeof(task->device_type) - 1] = '\0';
            } else {
                if (port_bitmap_has(&pb, 3306)) strcpy(task->device_type, "MySQL数据库服务器");
                else if (port_bitmap_has(&pb, 5432)) strcpy(task->device_type, "PostgreSQL数据库服务器");
                else if (port_bitmap_has(&pb, 6379)) strcpy(task->device_type, "Redis缓存服务器");
                else if (port_bitmap_has(&pb, 27017)) strcpy(task->device_type, "MongoDB数据库服务器");
                else if (port_bitmap_has(&pb, 1521)) strcpy(task->device_type, "Oracle数据库服务器");
                else strcpy(task->device_type, "数据库服务器");
            }
        }
        /* 容器/虚拟化平台 */
        else if (port_bitmap_has(&pb, 2375) || port_bitmap_has(&pb, 2376)) {
            strcpy(task->device_type, "Docker容器主机");
        }
        /* 大数据平台 */
        else if (port_bitmap_has(&pb, 9200) || port_bitmap_has(&pb, 50070) ||
                 port_bitmap_has(&pb, 2181)) {
            if (port_bitmap_has(&pb, 9200)) strcpy(task->device_type, "Elasticsearch集群节点");
            else if (port_bitmap_has(&pb, 50070)) strcpy(task->device_type, "Hadoop集群节点");
            else if (port_bitmap_has(&pb, 2181)) strcpy(task->device_type, "Zookeeper集群节点");
            else strcpy(task->device_type, "大数据平台");
        }
        /* Web服务器 */
        else if (port_bitmap_has(&pb, 80) || port_bitmap_has(&pb, 443) ||
                 port_bitmap_has(&pb, 8080) || port_bitmap_has(&pb, 8000) ||
                 port_bitmap_has(&pb, 3000) || port_bitmap_has(&pb, 9090)) {

            int web_port_count = 0;
            if (port_bitmap_has(&pb, 80)) web_port_count++;
            if (port_bitmap_has(&pb, 443)) web_port_count++;
            if (port_bitmap_has(&pb, 8080)) web_port_count++;

            if (port_bitmap_has(&pb, 3000)) strcpy(task->device_type, "Node.js应用服务器");
            else if (port_bitmap_has(&pb, 9090)) strcpy(task->device_type, "Prometheus监控服务器");
            else if (port_bitmap_has(&pb, 5000)) strcpy(task->device_type, "Python应用服务器");
            else if (web_port_count >= 2) strcpy(task->device_type, "Web应用服务器");
            else strcpy(task->device_type, "Web服务器");
        }
        /* 文件服务器 */
        else if (port_bitmap_has(&pb, 21) || port_bitmap_has(&pb, 2049) ||
                 port_bitmap_has(&pb, 445)) {
            if (port_bitmap_has(&pb, 2049)) strcpy(task->device_type, "NFS文件服务器");
            else strcpy(task->device_type, "文件服务器");
        }
        /* VNC远程桌面 */
        else if (port_bitmap_has(&pb, 5900)) {
            strcpy(task->device_type, "VNC远程桌面主机");
        }
        /* 邮件服务器 */
        else if (port_bitmap_has(&pb, 25) || port_bitmap_has(&pb, 110) ||
                 port_bitmap_has(&pb, 143) || port_bitmap_has(&pb, 993)) {
            strcpy(task->device_type, "邮件服务器");
        }
        /* DNS服务器 */
        else if (port_bitmap_has(&pb, 53)) {
            strcpy(task->device_type, "DNS服务器");
        }
        /* 普通Linux主机 */
        else {
            strcpy(task->device_type, "Linux主机");
        }
    }
    /* 仅Web服务（无SSH，可能是嵌入式或精简系统） */
    else if (port_bitmap_has(&pb, 80) || port_bitmap_has(&pb, 443)) {
        if (task->os_type[0] == '\0') strcpy(task->os_type, "未知");
        strcpy(task->device_type, "Web服务/嵌入式设备");
    }
    /* 未知设备 */
    else {
        if (task->os_type[0] == '\0') strcpy(task->os_type, "未知");
        strcpy(task->device_type, "未知设备");
    }
}

/* 解析主机名（使用非阻塞方式，设置超时避免长时间阻塞） */
void get_hostname_for_ip(const char *ip, char *hostname, size_t len) {
    hostname[0] = '\0';

    if (!config.resolve_hostname) {
        return;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;

    /* IP地址转换错误处理 */
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        return;
    }

    /* 使用fork子进程进行DNS查询，避免阻塞主线程 */
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        /* pipe创建失败，放弃解析 */
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        /* fork失败，关闭pipe并返回 */
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0) {
        /* 子进程：执行DNS查询 */
        close(pipefd[0]); /* 关闭读端 */

        char result[256];
        result[0] = '\0';

        /* 设置子进程超时（避免DNS查询永久阻塞） */
        alarm(2); /* 2秒超时 */

        /* 执行DNS查询 */
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), result, sizeof(result),
                       NULL, 0, NI_NAMEREQD) == 0) {
            /* 查询成功，写入管道 */
            ssize_t write_ret = write(pipefd[1], result, strlen(result) + 1);
            (void)write_ret;  /* Explicitly ignore - pipe write in child process */
        }

        close(pipefd[1]);
        _exit(0); /* 子进程退出 */
    } else {
        /* 父进程：等待子进程结果 */
        close(pipefd[1]); /* 关闭写端 */

        /* 设置读取超时 */
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(pipefd[0], &readfds);
        tv.tv_sec = 2;  /* 2秒超时 */
        tv.tv_usec = 0;

        int ret = select(pipefd[0] + 1, &readfds, NULL, NULL, &tv);
        if (ret > 0 && FD_ISSET(pipefd[0], &readfds)) {
            /* 有数据可读 */
            ssize_t n = read(pipefd[0], hostname, len - 1);
            if (n > 0) {
                hostname[n] = '\0';
            }
        }
        /* 超时或错误，hostname保持为空字符串 */

        close(pipefd[0]);

        /* 尝试立即回收子进程（快速路径）
         * 注意：如果子进程还在运行，WNOHANG会立即返回0
         * 但不用担心僵尸进程，因为main()中设置了SA_NOCLDWAIT
         * 内核会在子进程退出时自动回收 */
        int status;
        waitpid(pid, &status, WNOHANG);
    }
}

/* 并发端口扫描函数：对在线主机进行全端口扫描 */
static int scan_all_ports(ScanTask *task) {
    int sockets[ports_count];
    int open_port_indices[MAX_PORTS];
    int current_open_port_count = 0;
    fd_set write_fds;
    int max_fd = 0;
    struct timeval timeout;

    /* 初始化socket数组为-1，标记未使用 */
    for (int i = 0; i < ports_count; ++i) {
        sockets[i] = -1;
    }

    FD_ZERO(&write_fds);

    /* 为所有端口发起连接 */
    for (int i = 0; i < ports_count; ++i) {
        sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockets[i] < 0) {
            /* socket创建失败，跳过此端口 */
            continue;
        }

        /* 设置socket选项以提高性能 */
        int opt = 1;
        setsockopt(sockets[i], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        /* 设置非阻塞模式 */
        if (set_nonblocking(sockets[i]) != 0) {
            close(sockets[i]);
            sockets[i] = -1;
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)ports[i].port);

        /* 转换IP地址，添加错误处理 */
        if (inet_pton(AF_INET, task->ip, &addr.sin_addr) != 1) {
            close(sockets[i]);
            sockets[i] = -1;
            continue;
        }

        /* 尝试连接 */
        int ret = connect(sockets[i], (struct sockaddr*)&addr, sizeof(addr));
        if (ret == 0) {
            /* 连接立即成功（罕见情况） */
            if (current_open_port_count < MAX_PORTS) {
                open_port_indices[current_open_port_count++] = i;
            }
            close(sockets[i]);
            sockets[i] = -1;
        } else if (ret < 0 && errno == EINPROGRESS) {
            /* 连接进行中，加入select监控 */
            FD_SET(sockets[i], &write_fds);
            if (sockets[i] > max_fd) {
                max_fd = sockets[i];
            }
        } else {
            /* 连接失败 */
            close(sockets[i]);
            sockets[i] = -1;
        }
    }

    /* 如果没有待监控的socket，直接返回 */
    if (max_fd == 0) {
        goto cleanup;
    }

    /* 设置select超时 */
    timeout.tv_sec = TIMEOUT_MS / 1000;
    timeout.tv_usec = (TIMEOUT_MS % 1000) * 1000;

    int sret = select(max_fd + 1, NULL, &write_fds, NULL, &timeout);

    if (sret > 0) {
        for (int i = 0; i < ports_count; ++i) {
            if (sockets[i] < 0) continue;

            if (FD_ISSET(sockets[i], &write_fds)) {
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                if (getsockopt(sockets[i], SOL_SOCKET, SO_ERROR, &so_error, &len) == 0) {
                    if (so_error == 0) {
                        if (current_open_port_count < MAX_PORTS) {
                            open_port_indices[current_open_port_count++] = i;
                        }
                    }
                }
            }
        }
    } else if (sret < 0) {
        /* select出错 */
        /* 继续清理资源 */
    }
    /* sret == 0: 超时，所有未完成的连接都失败 */

cleanup:
    /* 清理所有socket */
    for (int i = 0; i < ports_count; ++i) {
        if (sockets[i] >= 0) {
            close(sockets[i]);
        }
    }

    /* 更新任务结果 */
    task->port_count = current_open_port_count;
    for (int i = 0; i < task->port_count; ++i) {
        task->open_ports[i] = open_port_indices[i];
        pthread_mutex_lock(&stats_mutex);
        stats.total_ports++;
        pthread_mutex_unlock(&stats_mutex);
    }

    return current_open_port_count;
}

/* 单个扫描线程函数 */
void* scan_thread(void *arg) {
    ScanTask *task = (ScanTask*)arg;
    long rt = 0;

    /* 初始化任务结构 */
    task->mac[0] = '\0';
    task->mac_vendor[0] = '\0';
    task->os_type[0] = '\0';
    task->device_type[0] = '\0';
    task->banner[0] = '\0';
    task->port_count = 0;
    task->is_alive = 0;
    task->response_time_ms = 0;
    task->hostname[0] = '\0';

    /* 第一步：快速检测主机在线性（只探测少量常见端口） */
    const int probe_ports[] = {80, 22, 443, 3389};
    for (size_t i = 0; i < sizeof(probe_ports) / sizeof(probe_ports[0]); ++i) {
        if (check_port(task->ip, probe_ports[i], &rt)) {
            task->is_alive = 1;
            task->response_time_ms = rt;
            break;
        }
    }

    /* 如果主机离线，直接返回 */
    if (!task->is_alive) {
        if (config.show_offline) {
            pthread_mutex_lock(&print_mutex);
            printf("  \033[31m○\033[0m \033[37m%s\033[0m [\033[31m离线\033[0m]\n", task->ip);
            pthread_mutex_unlock(&print_mutex);
        }
        return NULL;
    }

    /* 第二步：主机在线，进行全端口扫描 */
    scan_all_ports(task);

    /* 第三步：获取主机详细信息 */
    get_hostname_for_ip(task->ip, task->hostname, sizeof(task->hostname));
    get_remote_mac(task->ip, task->mac);

    /* 查询MAC厂商并获取设备类型提示 */
    if (task->mac[0] != '\0') {
        char device_hint[64];
        const char *vendor = lookup_mac_vendor(task->mac, device_hint);
        strncpy(task->mac_vendor, vendor, sizeof(task->mac_vendor) - 1);
        task->mac_vendor[sizeof(task->mac_vendor) - 1] = '\0';
    }

    /* 第四步：尝试获取服务Banner */
    for (int i = 0; i < task->port_count; ++i) {
        int p_idx = task->open_ports[i];
        int p = ports[p_idx].port;
        /* 只对特定服务端口抓取banner */
        if (p == 80 || p == 8080 || p == 8000 || p == 3000 || p == 22 || p == 21) {
            if (get_service_banner(task->ip, p, task->banner, sizeof(task->banner))) {
                break;
            }
        }
    }

    /* 第五步：OS指纹识别 */
    detect_os_enhanced(task);

    return NULL;
}

/* 打印进度条（仅 verbose） */
void print_progress(int current, int total) {
    if (!config.verbose) return;
    int percent = (int)((long long)current * 100 / (total ? total : 1));
    const int width = 40;
    int filled = (current * width) / (total ? total : 1);
    printf("\r  进度: [");
    for (int i=0;i<width;i++) putchar(i < filled ? '#' : '-');
    printf("] %3d%%", percent);
    fflush(stdout);
}

/* 扫描某个网段（主函数） */
void scan_subnet(NetworkInterface *iface) {
    stats.total_scanned = 0;
    stats.alive_hosts = 0;
    stats.total_ports = 0;
    stats.start_time = time(NULL);

    printf("\n\033[34m┌─ 网络接口信息 ─────────────────────────────────\033[0m\n");
    printf("\033[34m│\033[0m 接口名称:   \033[37m%-20s\033[0m \033[34m│\033[0m\n", iface->name);
    printf("\033[34m│\033[0m 本机IP:     \033[37m%-20s\033[0m \033[34m│\033[0m\n", iface->ip);
    printf("\033[34m│\033[0m 子网掩码:   \033[37m%-20s\033[0m \033[34m│\033[0m\n", iface->netmask);
    printf("\033[34m│\033[0m MAC地址:    \033[37m%-20s\033[0m \033[34m│\033[0m\n", iface->mac);
    printf("\033[34m│\033[0m 网络地址:   \033[37m%-20s\033[0m \033[34m│\033[0m\n", iface->network);
    printf("\033[34m│\033[0m 扫描端口数: \033[37m%-20d\033[0m \033[34m│\033[0m\n", ports_count);
    printf("\033[34m│\033[0m 最大并发数: \033[37m%-20d\033[0m \033[34m│\033[0m\n", MAX_THREADS);
    printf("\033[34m└───────────────────────────────────────────────\033[0m\n");

    struct in_addr netaddr;
    if (inet_pton(AF_INET, iface->network, &netaddr) != 1) {
        fprintf(stderr, "\033[31m[错误] 计算网络地址失败:\033[0m %s\n", iface->network);
        return;
    }
    unsigned int base = ntohl(netaddr.s_addr);

    int max_hosts = calculate_host_count(iface->netmask);
    if (max_hosts <= 0) {
        printf("\033[31m[警告] 无需扫描: 主机数为 0\033[0m\n");
        return;
    }
    stats.total_scanned = max_hosts;
    printf("\n\033[34m[信息] 正在扫描 %d 个主机...\033[0m\n", max_hosts);

    ScanTask *tasks = calloc(max_hosts, sizeof(ScanTask));
    pthread_t *threads = malloc(sizeof(pthread_t) * max_hosts);
    if (!tasks || !threads) {
        perror("malloc");
        free(tasks);
        free(threads);
        return;
    }

    for (int i = 0; i < max_hosts; i += MAX_THREADS) {
        int batch_size = (i + MAX_THREADS > max_hosts) ? (max_hosts - i) : MAX_THREADS;
        for (int j = 0; j < batch_size; ++j) {
            int idx = i + j;
            struct in_addr a;
            a.s_addr = htonl(base + idx + 1);
            inet_ntop(AF_INET, &a, tasks[idx].ip, sizeof(tasks[idx].ip));
            pthread_create(&threads[idx], NULL, scan_thread, &tasks[idx]);
        }
        for (int j = 0; j < batch_size; ++j) {
            int idx = i + j;
            pthread_join(threads[idx], NULL);
        }
        if (config.verbose) print_progress(i + batch_size, max_hosts);
    }
    if (config.verbose) printf("\n");

    /* 统计在线主机 */
    for (int i = 0; i < max_hosts; ++i) {
        if (tasks[i].is_alive) stats.alive_hosts++;
    }

    /* 输出整齐的表格（简化版）*/
    if (stats.alive_hosts > 0) {
        printf("\n\033[32m[发现] %d 台在线主机:\033[0m\n", stats.alive_hosts);
        for (int i = 0; i < max_hosts; ++i) {
            if (!tasks[i].is_alive) continue;
            
            // 确定显示的标识（主机名或MAC地址）
            char identifier[256];
            if (tasks[i].hostname[0]) {
                snprintf(identifier, sizeof(identifier), "%s", tasks[i].hostname);
            } else if (tasks[i].mac[0]) {
                snprintf(identifier, sizeof(identifier), "%s", tasks[i].mac);
            } else {
                snprintf(identifier, sizeof(identifier), "%s", "<未知>");
            }
            
            printf("\n\033[37m●\033[0m \033[37m%s\033[0m [\033[37m%s\033[0m]\n",
                   tasks[i].ip, identifier);

            /* 显示MAC地址和厂商信息 */
            if (tasks[i].mac[0] && tasks[i].mac_vendor[0]) {
                printf("  MAC地址: \033[37m%s\033[0m (\033[36m%s\033[0m)\n",
                       tasks[i].mac, tasks[i].mac_vendor);
            } else if (tasks[i].mac[0]) {
                printf("  MAC地址: \033[37m%s\033[0m\n", tasks[i].mac);
            }

            printf("  响应时间: \033[37m%ldms\033[0m | 开放端口: \033[37m%d\033[0m 个\n",
                   tasks[i].response_time_ms, tasks[i].port_count);
                   
            if (tasks[i].port_count > 0) {
                printf("  开放端口: ");
                for (int k=0; k<tasks[i].port_count; k++) {
                    int pi = tasks[i].open_ports[k];
                    if (k > 0) printf(", ");
                    printf("\033[37m%d\033[0m(\033[37m%s\033[0m)", ports[pi].port, ports[pi].service);
                }
                printf("\n");
            }
            if (tasks[i].banner[0]) {
                printf("  Banner: \033[37m%s\033[0m\n", tasks[i].banner);
            }
            if (tasks[i].os_type[0]) {
                printf("  系统类型: \033[37m%s\033[0m | 设备类型: \033[37m%s\033[0m\n", tasks[i].os_type, tasks[i].device_type);
            }
        }
    } else {
        printf("\n\033[31m[信息] 未发现在线主机\033[0m\n");
    }

    stats.end_time = time(NULL);
    printf("\n\033[34m┌─ 扫描统计信息 ────────────────────────────────\033[0m\n");
    printf("\033[34m│\033[0m 主机: \033[37m%d/%d\033[0m | 端口: \033[37m%d\033[0m 个 | 用时: \033[37m%ld\033[0m 秒\n",
           stats.alive_hosts, stats.total_scanned, stats.total_ports,
           stats.end_time - stats.start_time);
    printf("\033[34m└───────────────────────────────────────────────\033[0m\n");
}

void print_usage(const char *prog) {
    printf("\n\033[34m┌─ 内网扫描与主机识别工具 ───────────────────────\033[0m\n");
    printf("\033[34m│\033[0m 用法: \033[37m%s\033[0m [选项]\n", prog);
    printf("\033[34m├─ 命令选项 ───────────────────────────────────\033[0m\n");
    printf("\033[34m│\033[0m \033[37m-a, --auto\033[0m           自动扫描所有内网网卡 (默认)\n");
    printf("\033[34m│\033[0m \033[37m-i <if>\033[0m              仅扫描指定网卡\n");
    printf("\033[34m│\033[0m \033[37m-l, --list\033[0m           列出所有内网网卡信息\n");
    printf("\033[34m│\033[0m \033[37m-v, --verbose\033[0m        显示详细信息和进度条\n");
    printf("\033[34m│\033[0m \033[37m-o, --offline\033[0m        显示离线主机\n");
    printf("\033[34m│\033[0m \033[37m--no-resolve\033[0m         不解析主机名 (更快)\n");
    printf("\033[34m│\033[0m \033[37m--no-os\033[0m              不检测操作系统\n");
    printf("\033[34m│\033[0m \033[37m-h, --help\033[0m           帮助\n");
    printf("\033[34m└───────────────────────────────────────────────\033[0m\n");
}

int main(int argc, char *argv[]) {
    NetworkInterface interfaces[MAX_IFACES];
    int iface_count;
    int mode = 0; /* 0=scan all, 1=list, 2=specific if */
    
    char target_iface[32];
    target_iface[0] = '\0';

    printf("\n\033[34m┌────────────────────────────┐\033[0m\n");
    printf(  "\033[34m│\033[0m \033[37m内网扫描与主机识别工具\033[0m     \033[34m│\033[0m\n");
    printf(  "\033[34m└────────────────────────────┘\033[0m\n");

    /* 设置SA_NOCLDWAIT防止fork的DNS查询子进程变成僵尸进程
     * 当子进程退出时，内核会自动回收，无需父进程wait */
    struct sigaction sa;
    sa.sa_handler = SIG_DFL;
#ifdef SA_NOCLDWAIT
    sa.sa_flags = SA_NOCLDWAIT;
#else
    sa.sa_flags = 0;
#endif
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("sigaction");
    }

    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i], "-h")==0 || strcmp(argv[i], "--help")==0) { print_usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "-l")==0 || strcmp(argv[i], "--list")==0) mode = 1;
        else if (strcmp(argv[i], "-i")==0 && i+1<argc) { 
            mode = 2; 
            strncpy(target_iface, argv[++i], sizeof(target_iface)-1);
            target_iface[sizeof(target_iface)-1] = '\0'; // 确保字符串结束符
        }
        else if (strcmp(argv[i], "-v")==0 || strcmp(argv[i], "--verbose")==0) config.verbose = 1;
        else if (strcmp(argv[i], "-o")==0 || strcmp(argv[i], "--offline")==0) config.show_offline = 1;
        else if (strcmp(argv[i], "--no-resolve")==0) config.resolve_hostname = 0;
        else if (strcmp(argv[i], "--no-os")==0) config.detect_os = 0;
    }

    printf("\n\033[34m[信息] 正在检测内网接口...\033[0m\n");
    iface_count = get_network_interfaces(interfaces, MAX_IFACES);
    if (iface_count <= 0) {
        fprintf(stderr, "\033[31m[错误] 未找到可用的内网网络接口\033[0m\n");
        return 1;
    }
    printf("\033[32m[成功] 发现 %d 个内网网络接口\033[0m\n", iface_count);

    if (mode == 1) {
        printf("\n\033[34m┌─ 网络接口列表 ────────────────────────────────\033[0m\n");
        printf("\033[34m│\033[0m \033[37m%-4s %-12s %-15s %-17s %-15s %-15s\033[0m\n", 
               "序号", "网卡名称", "IP地址", "MAC地址", "子网掩码", "网络地址");
        printf("\033[34m├───────────────────────────────────────────────\033[0m\n");
        for (int i=0; i<iface_count; i++) {
            printf("\033[34m│\033[0m \033[37m%-4d %-12s %-15s %-17s %-15s %-15s\033[0m\n",
                   i+1, interfaces[i].name, interfaces[i].ip, interfaces[i].mac, interfaces[i].netmask, interfaces[i].network);
        }
        printf("\033[34m└───────────────────────────────────────────────\033[0m\n");
        return 0;
    }

    if (mode == 2) {
        int found = 0;
        for (int i=0; i<iface_count; i++) {
            if (strcmp(interfaces[i].name, target_iface)==0) {
                scan_subnet(&interfaces[i]);
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "\033[31m[错误] 未找到网卡 '%s'\033[0m\n", target_iface);
            return 1;
        }
    } else {
        for (int i=0; i<iface_count; i++) {
            scan_subnet(&interfaces[i]);
        }
    }

    printf("\n\033[32m[完成] 所有扫描任务完成！\033[0m\n");
    return 0;
}
