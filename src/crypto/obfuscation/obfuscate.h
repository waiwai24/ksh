#ifndef OBFUSCATE_H
#define OBFUSCATE_H

#include <stdint.h>
#include <unistd.h>

/* ===== 1. 字符串加密系统 ===== */

/* 编译时密钥生成 (基于 __LINE__ 和 index，确保加密/解密密钥一致) */
#define OBF_KEY(index) (uint8_t)(0x5A ^ ((__LINE__ * 71) + (index) * 37))

/* 字符加密宏 */
#define OBF_CHAR(c, i) ((c) ^ OBF_KEY(i))

/* 字符串加密宏 - 最多支持64字节字符串 */
#define OBFSTR(str) ({ \
    static volatile uint8_t _obf_data[] = { \
        OBF_CHAR(((sizeof(str) > 0)  ? str[0]  : 0), 0),  \
        OBF_CHAR(((sizeof(str) > 1)  ? str[1]  : 0), 1),  \
        OBF_CHAR(((sizeof(str) > 2)  ? str[2]  : 0), 2),  \
        OBF_CHAR(((sizeof(str) > 3)  ? str[3]  : 0), 3),  \
        OBF_CHAR(((sizeof(str) > 4)  ? str[4]  : 0), 4),  \
        OBF_CHAR(((sizeof(str) > 5)  ? str[5]  : 0), 5),  \
        OBF_CHAR(((sizeof(str) > 6)  ? str[6]  : 0), 6),  \
        OBF_CHAR(((sizeof(str) > 7)  ? str[7]  : 0), 7),  \
        OBF_CHAR(((sizeof(str) > 8)  ? str[8]  : 0), 8),  \
        OBF_CHAR(((sizeof(str) > 9)  ? str[9]  : 0), 9),  \
        OBF_CHAR(((sizeof(str) > 10) ? str[10] : 0), 10), \
        OBF_CHAR(((sizeof(str) > 11) ? str[11] : 0), 11), \
        OBF_CHAR(((sizeof(str) > 12) ? str[12] : 0), 12), \
        OBF_CHAR(((sizeof(str) > 13) ? str[13] : 0), 13), \
        OBF_CHAR(((sizeof(str) > 14) ? str[14] : 0), 14), \
        OBF_CHAR(((sizeof(str) > 15) ? str[15] : 0), 15), \
        OBF_CHAR(((sizeof(str) > 16) ? str[16] : 0), 16), \
        OBF_CHAR(((sizeof(str) > 17) ? str[17] : 0), 17), \
        OBF_CHAR(((sizeof(str) > 18) ? str[18] : 0), 18), \
        OBF_CHAR(((sizeof(str) > 19) ? str[19] : 0), 19), \
        OBF_CHAR(((sizeof(str) > 20) ? str[20] : 0), 20), \
        OBF_CHAR(((sizeof(str) > 21) ? str[21] : 0), 21), \
        OBF_CHAR(((sizeof(str) > 22) ? str[22] : 0), 22), \
        OBF_CHAR(((sizeof(str) > 23) ? str[23] : 0), 23), \
        OBF_CHAR(((sizeof(str) > 24) ? str[24] : 0), 24), \
        OBF_CHAR(((sizeof(str) > 25) ? str[25] : 0), 25), \
        OBF_CHAR(((sizeof(str) > 26) ? str[26] : 0), 26), \
        OBF_CHAR(((sizeof(str) > 27) ? str[27] : 0), 27), \
        OBF_CHAR(((sizeof(str) > 28) ? str[28] : 0), 28), \
        OBF_CHAR(((sizeof(str) > 29) ? str[29] : 0), 29), \
        OBF_CHAR(((sizeof(str) > 30) ? str[30] : 0), 30), \
        OBF_CHAR(((sizeof(str) > 31) ? str[31] : 0), 31), \
        OBF_CHAR(((sizeof(str) > 32) ? str[32] : 0), 32), \
        OBF_CHAR(((sizeof(str) > 33) ? str[33] : 0), 33), \
        OBF_CHAR(((sizeof(str) > 34) ? str[34] : 0), 34), \
        OBF_CHAR(((sizeof(str) > 35) ? str[35] : 0), 35), \
        OBF_CHAR(((sizeof(str) > 36) ? str[36] : 0), 36), \
        OBF_CHAR(((sizeof(str) > 37) ? str[37] : 0), 37), \
        OBF_CHAR(((sizeof(str) > 38) ? str[38] : 0), 38), \
        OBF_CHAR(((sizeof(str) > 39) ? str[39] : 0), 39), \
        OBF_CHAR(((sizeof(str) > 40) ? str[40] : 0), 40), \
        OBF_CHAR(((sizeof(str) > 41) ? str[41] : 0), 41), \
        OBF_CHAR(((sizeof(str) > 42) ? str[42] : 0), 42), \
        OBF_CHAR(((sizeof(str) > 43) ? str[43] : 0), 43), \
        OBF_CHAR(((sizeof(str) > 44) ? str[44] : 0), 44), \
        OBF_CHAR(((sizeof(str) > 45) ? str[45] : 0), 45), \
        OBF_CHAR(((sizeof(str) > 46) ? str[46] : 0), 46), \
        OBF_CHAR(((sizeof(str) > 47) ? str[47] : 0), 47), \
        OBF_CHAR(((sizeof(str) > 48) ? str[48] : 0), 48), \
        OBF_CHAR(((sizeof(str) > 49) ? str[49] : 0), 49), \
        OBF_CHAR(((sizeof(str) > 50) ? str[50] : 0), 50), \
        OBF_CHAR(((sizeof(str) > 51) ? str[51] : 0), 51), \
        OBF_CHAR(((sizeof(str) > 52) ? str[52] : 0), 52), \
        OBF_CHAR(((sizeof(str) > 53) ? str[53] : 0), 53), \
        OBF_CHAR(((sizeof(str) > 54) ? str[54] : 0), 54), \
        OBF_CHAR(((sizeof(str) > 55) ? str[55] : 0), 55), \
        OBF_CHAR(((sizeof(str) > 56) ? str[56] : 0), 56), \
        OBF_CHAR(((sizeof(str) > 57) ? str[57] : 0), 57), \
        OBF_CHAR(((sizeof(str) > 58) ? str[58] : 0), 58), \
        OBF_CHAR(((sizeof(str) > 59) ? str[59] : 0), 59), \
        OBF_CHAR(((sizeof(str) > 60) ? str[60] : 0), 60), \
        OBF_CHAR(((sizeof(str) > 61) ? str[61] : 0), 61), \
        OBF_CHAR(((sizeof(str) > 62) ? str[62] : 0), 62), \
        OBF_CHAR(((sizeof(str) > 63) ? str[63] : 0), 63), \
        0 \
    }; \
    static char _obf_buf[sizeof(str)]; \
    for (size_t _i = 0; _i < sizeof(str) - 1 && _i < 64; _i++) { \
        _obf_buf[_i] = _obf_data[_i] ^ OBF_KEY(_i); \
    } \
    _obf_buf[sizeof(str) - 1] = '\0'; \
    (char*)_obf_buf; \
})

/* ===== 2. 端口号混淆 ===== */

/* 端口号混淆 - 编译时混淆 */
#define OBF_PORT(port) ((port) ^ 0xA5B3)

/* 端口号解混淆 - 运行时使用 */
#define DEOBF_PORT(obf_port) ((obf_port) ^ 0xA5B3)


/* ===== 3. 栈保护增强 ===== */

/* 插入随机栈数据以干扰栈分析 */
#define STACK_NOISE() \
    do { \
        volatile char _noise[64]; \
        for (int _i = 0; _i < 64; _i++) { \
            _noise[_i] = (char)(getpid() ^ _i); \
        } \
        (void)_noise[0]; \
    } while (0)


#endif /* OBFUSCATE_H */
