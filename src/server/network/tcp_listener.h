#ifndef TCP_LISTENER_H
#define TCP_LISTENER_H

#include <pthread.h>

/* TCP网络监听函数 */
void* network_listener_thread(void* arg);
void* handle_client_connection(void* arg);

#endif /* TCP_LISTENER_H */
