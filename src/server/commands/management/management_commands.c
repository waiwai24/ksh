#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "management_commands.h"
#include "../../managers/client/client_manager.h"
#include "../../managers/plugin/plugin_manager.h"
#include "../../utils/output_writer.h"

/* 管理命令表 */
static struct management_command_entry management_commands[] = {
    { "!",          cmd_command,    "Run commands in the current system" },
    { "list",       cmd_list,       "List clients" },
    { "entry",      cmd_entry,      "Enter specified num client control terminal" },
    { "delete",     cmd_delete,     "Delete client by ID" },
    { "plugin",     cmd_plugin,     "Show available plugins" },
    { "disconnect", cmd_disconnect, "Exit client but keep daemon running" },
    { "quit",       cmd_quit,       "Stop daemon" },
    { "help",       cmd_help,       "Show available commands" },
    { NULL, NULL, NULL }
};

/* 导出管理命令表 */
struct management_command_entry* get_management_commands(void) {
    return management_commands;
}

/* 外部全局变量（由core/daemon.c定义） */
extern int daemon_running;

int cmd_command(int client_fd, const char *args, session_state_t *session) {
    (void)session;

    if (!args || strlen(args) == 0) {
        char buffer[256];
        output_writer_t writer;
        writer_init(&writer, buffer, sizeof(buffer));
        writer_printf(&writer, "Usage: ! <shell_command>\n\n");
        return writer_flush_with_return(&writer, client_fd, 0);
    }

    FILE *fp;
    char command[1024];

    snprintf(command, sizeof(command), "%s 2>&1", args);

    fp = popen(command, "r");
    if (fp == NULL) {
        char buffer[256];
        output_writer_t writer;
        writer_init(&writer, buffer, sizeof(buffer));
        writer_printf(&writer, "Failed to execute command: %s\n\n", args);
        return writer_flush_with_return(&writer, client_fd, 0);
    }

    /* 使用固定大小缓冲区 (8KB) */
    char buffer[8192];
    output_writer_t writer;
    writer_init(&writer, buffer, sizeof(buffer));

    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        writer_printf(&writer, "%s", line);
        if (writer_has_overflow(&writer)) {
            break;  // 缓冲区已满，停止读取
        }
    }

    pclose(fp);

    if (writer_has_overflow(&writer)) {
        if (writer_length(&writer) > 100) {
            writer.offset -= 50;
            writer_printf(&writer, "\n... (output truncated)\n");
        }
    }

    writer_printf(&writer, "\n");
    return writer_flush_with_return(&writer, client_fd, 0);
}
int cmd_list(int client_fd, const char *args, session_state_t *session) {
    (void)args;

    if (!session->client_mgr) {
        dprintf(client_fd, "Client manager not available\n\n");
        return 1;
    }

    char buffer[4096];
    output_writer_t writer;
    writer_init(&writer, buffer, sizeof(buffer));

    writer_printf(&writer, "%-4s %-18s %-8s %-16s %-24s %-24s %-6s\n",
                  "ID", "IP_Address", "Country", "Hostname", "OS", "Last_Activity", "Alive");
    writer_printf(&writer, "%-4s %-18s %-8s %-16s %-24s %-24s %-6s\n",
                  "----", "------------------", "--------", "----------------",
                  "------------------------", "------------------------", "------");

    int valid_count = 0;
    for (int i = 0; i < session->client_mgr->client_count; i++) {
        client_info_t *client = &session->client_mgr->clients[i];

        if (client->client_id == -1) {
            continue;
        }

        struct tm *tm_info = localtime(&client->last_activity);
        char time_str[24];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

        const char *status_str = (client->is_alive == 1) ? "Yes" : "No";

        writer_printf(&writer, "%-4d %-18s %-8s %-16.16s %-24.24s %-24s %-6s\n",
                      client->client_id,
                      client->ip_address,
                      client->country,
                      client->hostname,
                      client->os,
                      time_str,
                      status_str);

        valid_count++;
        if (writer_has_overflow(&writer)) break;
    }

    writer_printf(&writer, "\nTotal clients: %d\n\n", valid_count);

    return writer_flush_with_return(&writer, client_fd, 0);
}

int cmd_entry(int client_fd, const char *args, session_state_t *session) {
    if (!args || strlen(args) == 0) {
        dprintf(client_fd, "Usage: entry <client_id>\n\n");
        return 0;
    }

    int client_id = atoi(args);
    if (client_id < 0) {
        dprintf(client_fd, "Invalid client ID: %s\n\n", args);
        return 0;
    }

    int result = enter_client_session(session, client_id);
    if (result == 0) {
        dprintf(client_fd, "Entered client %d session. Type 'help' for client commands, 'exit' to leave.\n\n", client_id);
    } else if (result == -2) {
        dprintf(client_fd, "Client %d not found\n\n", client_id);
    } else if (result == -3) {
        dprintf(client_fd, "Client %d is not connected\n\n", client_id);
    } else if (result == -4) {
        dprintf(client_fd, "Client %d is already in use by another administrator. Please try again later.\n\n", client_id);
    } else {
        dprintf(client_fd, "Failed to enter client %d session\n\n", client_id);
    }

    return 0;
}
int cmd_delete(int client_fd, const char *args, session_state_t *session) {
    if (!session->client_mgr) {
        dprintf(client_fd, "Client manager not available\n\n");
        return 1;
    }

    if (!args || strlen(args) == 0) {
        dprintf(client_fd, "Usage: delete <client_id>\n\n");
        return 0;
    }

    int client_id = atoi(args);
    if (client_id < 0) {
        dprintf(client_fd, "Invalid client ID: %s\n\n", args);
        return 0;
    }

    int result = delete_client(session->client_mgr, client_id);
    if (result == 0) {
        dprintf(client_fd, "Client %d deleted successfully\n\n", client_id);
    } else if (result == -2) {
        dprintf(client_fd, "Cannot delete client %d: client is still connected\n\n", client_id);
    } else {
        dprintf(client_fd, "Failed to delete client %d (client not found)\n\n", client_id);
    }

    return 0;
}

int cmd_plugin(int client_fd, const char *args, session_state_t *session) {
    (void)args;

    if (!session->plugin_mgr) {
        char buffer[256];
        output_writer_t writer;
        writer_init(&writer, buffer, sizeof(buffer));
        writer_printf(&writer, "Plugin manager not available\n\n");
        return writer_flush_with_return(&writer, client_fd, 1);
    }

    char buffer[4096];
    output_writer_t writer;
    writer_init(&writer, buffer, sizeof(buffer));

    // 获取插件列表
    char plugin_output[4096];
    if (list_plugins(session->plugin_mgr, plugin_output, sizeof(plugin_output)) == 0) {
        writer_printf(&writer, "%s", plugin_output);
        writer_printf(&writer, "\nNote: To use plugins on client, upload and execute the plugin files\n\n");
    } else {
        writer_printf(&writer, "Failed to list plugins\n\n");
    }

    return writer_flush_with_return(&writer, client_fd, 0);
}

int cmd_disconnect(int client_fd, const char *args, session_state_t *session) {
    (void)args;
    (void)session;

    char buffer[256];
    output_writer_t writer;
    writer_init(&writer, buffer, sizeof(buffer));
    writer_printf(&writer, "Daemon will continue running in background\n\n");
    return writer_flush_with_return(&writer, client_fd, 0);
}

int cmd_quit(int client_fd, const char *args, session_state_t *session) {
    (void)args;
    (void)session;
    dprintf(client_fd, "\nDaemon quitting...\n\n");
    daemon_running = 0;
    return 1;
}

int cmd_help(int client_fd, const char *args, session_state_t *session) {
    (void)args;
    (void)session;

    char buffer[2048];
    output_writer_t writer;
    writer_init(&writer, buffer, sizeof(buffer));

    for (struct management_command_entry *c = management_commands; c->name; c++) {
        writer_printf(&writer, "    %s - %s\n", c->name, c->help);
        if (writer_has_overflow(&writer)) break;
    }
    writer_printf(&writer, "\n");

    return writer_flush_with_return(&writer, client_fd, 0);
}
