#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <fcntl.h>
#include <netdb.h>

#include "core/daemon.h"
#include "managers/client/client_manager.h"
#include "managers/plugin/plugin_manager.h"
#include "ui/interactive_terminal.h"
#include "../client/client.h"

client_manager_t g_client_manager;
plugin_manager_t g_plugin_manager;
void print_usage(const char *prog_name);

int main( int argc, char *argv[] )
{
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "--status") == 0) {
            if (is_daemon_running()) {
                printf("Daemon is running\n");
                return 0;
            } else {
                printf("Daemon is not running\n");
                return 1;
            }
        } else if (strcmp(argv[1], "-k") == 0 || strcmp(argv[1], "--kill") == 0) {
            FILE *fp = fopen(PID_FILE, "r");
            if (!fp) {
                printf("Daemon is not running\n");
                return 1;
            }

            pid_t pid;
            if (fscanf(fp, "%d", &pid) == 1) {
                fclose(fp);
                if (kill(pid, SIGTERM) == 0) {
                    printf("Daemon killed\n");
                    unlink(SOCKET_PATH);
                    return 0;
                } else {
                    perror("kill");
                    return 1;
                }
            } else {
                fclose(fp);
                printf("Invalid PID file\n");
                return 1;
            }
        } else if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--connect") == 0) {
            if (!is_daemon_running()) {
                printf("Daemon is not running. Start it first with -d option.\n");
                return 1;
            }
            interactive_mode();
            return 0;
        } else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--daemon") == 0) {
            if (is_daemon_running()) {
                printf("Daemon is already running\n");
                return 1;
            }

            pid_t daemon_pid = create_daemon();
            if (daemon_pid > 0) {
                write_pid_file(daemon_pid);
                printf("Daemon started with PID %d\n", daemon_pid);
                return 0;
            } else if (daemon_pid == 0) {
                if (init_client_manager(&g_client_manager) != 0) {
                    printf("Failed to initialize client manager\n");
                    return 1;
                }

                init_plugin_manager(&g_plugin_manager);

                daemon_loop(&g_client_manager, &g_plugin_manager);
                return 0;
            } else {
                printf("Failed to create daemon\n");
                return 1;
            }
        } else {
            printf("Unknown option: %s\n", argv[1]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (is_daemon_running()) {
        printf("Daemon is already running. Connecting...\n");
        interactive_mode();
    } else {
        pid_t daemon_pid = create_daemon();
        if (daemon_pid > 0) {
            write_pid_file(daemon_pid);
            printf("Daemon started with PID %d. Connecting...\n", daemon_pid);
            sleep(1);
            interactive_mode();
        } else if (daemon_pid == 0) {
            if (init_client_manager(&g_client_manager) != 0) {
                printf("Failed to initialize client manager\n");
                return 1;
            }

            init_plugin_manager(&g_plugin_manager);

            daemon_loop(&g_client_manager, &g_plugin_manager);
        } else {
            printf("Failed to create daemon\n");
            return 1;
        }
    }
    return 0;
}

void print_usage(const char *prog_name) 
{
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -d, --daemon    Start as daemon\n");
    printf("  -c, --connect   Connect to running daemon\n");
    printf("  -s, --status    Check daemon status\n");
    printf("  -k, --kill      Kill running daemon\n");
    printf("  -h, --help      Show this help\n");
}