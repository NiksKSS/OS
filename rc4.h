#ifndef RC4_H
#define RC4_H

#include <stddef.h>

typedef struct rc4_ctx rc4_ctx;

int rc4_init(rc4_ctx **ctx, const unsigned char *key, int key_len);

void rc4_encrypt(rc4_ctx *ctx, const unsigned char *in, unsigned char *out, int len);

void rc4_destroy(rc4_ctx *ctx);

void rc4_crypt(const unsigned char *key, int key_len,
               const unsigned char *in, unsigned char *out, int len);

#endif
