/* src/server/utils/output_writer.h */
#ifndef OUTPUT_WRITER_H
#define OUTPUT_WRITER_H

#include <stddef.h>
#include <stdarg.h>
#include <sys/types.h>

/* 会话模式类型 */
typedef enum {
    OUTPUT_MODE_NORMAL,
    OUTPUT_MODE_CLIENT,
    OUTPUT_MODE_SHELL
} output_mode_t;

/* 输出写入器结构 */
typedef struct {
    char *buffer;          // 缓冲区指针
    size_t capacity;       // 缓冲区总容量
    size_t offset;         // 当前写入位置
    int overflow;          // 是否发生溢出
} output_writer_t;

/* API 函数 */

/**
 * 初始化输出写入器
 * @param writer 写入器对象
 * @param buffer 外部缓冲区
 * @param size 缓冲区大小
 */
void writer_init(output_writer_t *writer, char *buffer, size_t size);

/**
 * 格式化写入数据（类似printf）
 * @param writer 写入器对象
 * @param format 格式化字符串
 * @return 实际写入的字节数，-1表示溢出
 */
int writer_printf(output_writer_t *writer, const char *format, ...);

/**
 * 添加模式提示符
 * @param writer 写入器对象
 * @param mode 会话模式
 * @param client_id 客户端ID（CLIENT/SHELL模式需要）
 */
void writer_add_prompt(output_writer_t *writer, output_mode_t mode, int client_id);

/**
 * 刷新输出到文件描述符
 * @param writer 写入器对象
 * @param fd 目标文件描述符
 * @return 写入的字节数，失败返回-1
 */
ssize_t writer_flush(output_writer_t *writer, int fd);

/**
 * 刷新输出并返回指定返回值（用于命令处理函数）
 * @param writer 写入器对象
 * @param fd 目标文件描述符
 * @param return_value 要返回的值（0=正常，4=已发送提示符）
 * @return return_value参数的值
 */
int writer_flush_with_return(output_writer_t *writer, int fd, int return_value);

/**
 * 获取当前已写入的数据长度
 */
static inline size_t writer_length(output_writer_t *writer) {
    return writer->offset;
}

/**
 * 检查是否发生溢出
 */
static inline int writer_has_overflow(output_writer_t *writer) {
    return writer->overflow;
}

/**
 * 重置写入器（复用缓冲区）
 */
static inline void writer_reset(output_writer_t *writer) {
    writer->offset = 0;
    writer->overflow = 0;
}

#endif /* OUTPUT_WRITER_H */
