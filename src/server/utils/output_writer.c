/* src/server/utils/output_writer.c */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "output_writer.h"

void writer_init(output_writer_t *writer, char *buffer, size_t size) {
    writer->buffer = buffer;
    writer->capacity = size;
    writer->offset = 0;
    writer->overflow = 0;
}

int writer_printf(output_writer_t *writer, const char *format, ...) {
    if (writer->overflow) {
        return -1;
    }

    size_t remaining = writer->capacity - writer->offset;
    if (remaining <= 1) {
        writer->overflow = 1;
        return -1;
    }

    va_list args;
    va_start(args, format);
    int written = vsnprintf(writer->buffer + writer->offset,
                           remaining,
                           format,
                           args);
    va_end(args);

    if (written < 0) {
        return -1;
    }

    if ((size_t)written >= remaining) {
        // 发生截断
        writer->overflow = 1;
        writer->offset = writer->capacity - 1;  // 保留null终止符
        return -1;
    }

    writer->offset += written;
    return written;
}

void writer_add_prompt(output_writer_t *writer, output_mode_t mode, int client_id) {
    switch (mode) {
        case OUTPUT_MODE_NORMAL:
            writer_printf(writer, "\001NORMAL_MODE\001");
            break;
        case OUTPUT_MODE_CLIENT:
            writer_printf(writer, "\001CLIENT_MODE:%d\001", client_id);
            break;
        case OUTPUT_MODE_SHELL:
            writer_printf(writer, "\001SHELL_MODE:%d\001", client_id);
            break;
    }
}

ssize_t writer_flush(output_writer_t *writer, int fd) {
    if (writer->offset == 0) {
        return 0;  // 没有数据需要写入
    }

    ssize_t result = write(fd, writer->buffer, writer->offset);

    if (result > 0) {
        writer_reset(writer);  // 写入成功后重置
    }

    return result;
}

int writer_flush_with_return(output_writer_t *writer, int fd, int return_value) {
    writer_flush(writer, fd);
    return return_value;
}
