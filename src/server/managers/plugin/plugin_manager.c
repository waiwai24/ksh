#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "plugin_manager.h"

/* 静态插件注册表 - 在此添加可用插件信息 */
static plugin_info_t static_plugins[] = {
    {"scan", "1.0", "Intranet scanner"},
    {"socks5", "1.0", "SOCKS5 proxy server"},
};

void init_plugin_manager(plugin_manager_t *manager) {
    if (!manager) {
        return;
    }

    memset(manager, 0, sizeof(plugin_manager_t));

    // 复制静态插件信息到管理器
    int count = sizeof(static_plugins) / sizeof(plugin_info_t);
    if (count > MAX_PLUGINS) {
        count = MAX_PLUGINS;
    }

    memcpy(manager->plugins, static_plugins, count * sizeof(plugin_info_t));
    manager->plugin_count = count;

    printf("Plugin manager initialized with %d plugins\n", count);
}

int list_plugins(plugin_manager_t *manager, char *output, size_t size) {
    if (!manager || !output) {
        return -1;
    }

    int offset = 0;

    offset += snprintf(output + offset, size - offset,
                      "%-20s %-10s %-50s\n",
                      "Name", "Version", "Description");

    offset += snprintf(output + offset, size - offset,
                      "%-20s %-10s %-50s\n",
                      "--------------------", "----------",
                      "--------------------------------------------------");

    for (int i = 0; i < manager->plugin_count; i++) {
        plugin_info_t *plugin = &manager->plugins[i];
        offset += snprintf(output + offset, size - offset,
                          "%-20s %-10s %-50s\n",
                          plugin->name,
                          plugin->version,
                          plugin->description);

        if ((size_t)offset >= size - 1) break;
    }

    offset += snprintf(output + offset, size - offset,
                      "\nTotal plugins: %d\n", manager->plugin_count);

    return 0;
}
