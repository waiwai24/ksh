#ifndef UNIX_SOCKET_H
#define UNIX_SOCKET_H

/* Unix Socket相关函数 */
int create_unix_socket(void);
int connect_to_daemon(void);

#endif /* UNIX_SOCKET_H */
