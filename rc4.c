#include <string.h>
#include <stdlib.h>
#include "rc4.h"

struct rc4_ctx {
    unsigned char S[256];
    int i, j;
};

static void rc4_ksa(unsigned char *S, const unsigned char *key, int key_len) {
    for (int i = 0; i < 256; i++)
        S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
    }
}

static unsigned char rc4_prga_byte(unsigned char *S, int *i, int *j) {
    *i = (*i + 1) % 256;
    *j = (*j + S[*i]) % 256;
    unsigned char t = S[*i]; S[*i] = S[*j]; S[*j] = t;
    return S[(S[*i] + S[*j]) % 256];
}

int rc4_init(rc4_ctx **ctx, const unsigned char *key, int key_len) {
    rc4_ctx *c = (rc4_ctx *)malloc(sizeof(rc4_ctx));
    if (!c) return -1;
    c->i = 0;
    c->j = 0;
    rc4_ksa(c->S, key, key_len);
    *ctx = c;
    return 0;
}

void rc4_encrypt(rc4_ctx *ctx, const unsigned char *in, unsigned char *out, int len) {
    for (int k = 0; k < len; k++)
        out[k] = in[k] ^ rc4_prga_byte(ctx->S, &ctx->i, &ctx->j);
}

void rc4_destroy(rc4_ctx *ctx) {
    if (!ctx) return;
    volatile unsigned char *p = ctx->S;
    memset((void *)p, 0, 256);
    ctx->i = ctx->j = 0;
    free(ctx);
}

void rc4_crypt(const unsigned char *key, int key_len,
               const unsigned char *in, unsigned char *out, int len) {
    unsigned char S[256];
    int i = 0, j = 0;
    rc4_ksa(S, key, key_len);
    for (int k = 0; k < len; k++)
        out[k] = in[k] ^ rc4_prga_byte(S, &i, &j);
    volatile unsigned char *p = S;
    memset((void *)p, 0, 256);
}
