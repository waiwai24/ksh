#ifndef _PEL_H
#define _PEL_H

#include "../aes/aes.h"

#define BUFSIZE 4096    /* maximum message length */
#define PEL_BUFFER_SIZE (BUFSIZE + 16 + 20)  /* buffer size for encryption */

#define PEL_SUCCESS 1
#define PEL_FAILURE 0

#define PEL_SYSTEM_ERROR        -1
#define PEL_CONN_CLOSED         -2
#define PEL_WRONG_CHALLENGE     -3
#define PEL_BAD_MSG_LENGTH      -4
#define PEL_CORRUPTED_DATA      -5
#define PEL_UNDEFINED_ERROR     -6

/* PEL context structure - per-session encryption state */
struct pel_context
{
    /* AES-CBC-128 variables */
    struct aes_context SK;      /* Rijndael session key  */
    unsigned char LCT[16];      /* last ciphertext block */

    /* HMAC-SHA1 variables */
    unsigned char k_ipad[64];   /* inner padding  */
    unsigned char k_opad[64];   /* outer padding  */
    unsigned long int p_cntr;   /* packet counter */
};

extern int pel_errno;

int pel_server_init( int client, const char *key,
                     struct pel_context *send_ctx, struct pel_context *recv_ctx );
int pel_client_init( int server, const char *key,
                     struct pel_context *send_ctx, struct pel_context *recv_ctx );

int pel_send_msg( int sockfd, unsigned char *msg, int length,
                  struct pel_context *send_ctx, unsigned char *buffer );
int pel_recv_msg( int sockfd, unsigned char *msg, int *length,
                  struct pel_context *recv_ctx, unsigned char *buffer );

#endif /* pel.h */
