#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#define MAX_PLUGINS 64
#define MAX_PLUGIN_NAME 64
#define MAX_PLUGIN_VERSION 16
#define MAX_PLUGIN_DESC 256

/* 插件信息结构（静态） */
typedef struct {
    char name[MAX_PLUGIN_NAME];            // 插件名称
    char version[MAX_PLUGIN_VERSION];      // 版本
    char description[MAX_PLUGIN_DESC];     // 描述
} plugin_info_t;

/* 插件管理器（简化版） */
typedef struct {
    plugin_info_t plugins[MAX_PLUGINS];
    int plugin_count;
} plugin_manager_t;

/* 插件管理器API（仅显示功能） */
void init_plugin_manager(plugin_manager_t *manager);
int list_plugins(plugin_manager_t *manager, char *output, size_t size);

#endif /* PLUGIN_MANAGER_H */