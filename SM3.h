#ifndef _GMSM_SM3_H_
#define _GMSM_SM3_H_

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SM3_DIGEST_LENGTH 32
#define SM3_BLOCK_SIZE 64
#define SM3_CBLOCK (SM3_BLOCK_SIZE)
#define SM3_HMAC_SIZE (SM3_DIGEST_LENGTH)

#ifndef HEADER_BYTEORDER_H
#define HEADER_BYTEORDER_H
#endif

#ifdef CPU_BIGENDIAN

#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#define be16_to_cpu(v) (v)
#define be32_to_cpu(v) (v)

#else

#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define le16_to_cpu(v) (v)
#define le32_to_cpu(v) (v)

#define cpu_to_be16(v) (((v) << 8) | ((v) >> 8))
#define cpu_to_be32(v) (((v) >> 24) | (((v) >> 8) & 0xff00) | (((v) << 8) & 0xff0000) | ((v) << 24))
#define be16_to_cpu(v) cpu_to_be16(v)
#define be32_to_cpu(v) cpu_to_be32(v)

#endif

struct SM3_CTX_t
{
    uint32_t digest[8];
    int nblocks;
    uint8_t block[64];
    int num;
};

struct SM3_HMAC_CTX_t
{
    SM3_CTX_t sm3_ctx;
    uint8_t key[SM3_BLOCK_SIZE];
};

class SM3
{
public:
    static void sm3_sum(const uint8_t *data, size_t datalen, uint8_t digest[SM3_DIGEST_LENGTH]);
    static void sm3_hmac(const uint8_t *data, size_t data_len,
                         const uint8_t *key, size_t key_len, uint8_t mac[SM3_HMAC_SIZE]);
    static int SM3HashWithPreprocess(const uint8_t *input, uint32_t input_byte_len,
                                     uint8_t *public_key, uint32_t public_key_byte_len,
                                     uint8_t *signer_ID, uint32_t signer_ID_byte_len,
                                     uint8_t *hash_value, uint32_t *hash_value_byte_len_pointer);

private:
    static void sm3_init(SM3_CTX_t *ctx);
    static void sm3_update(SM3_CTX_t *ctx, const uint8_t *data, size_t data_len);
    static void sm3_final(SM3_CTX_t *ctx, uint8_t digest[SM3_DIGEST_LENGTH]);
    static void sm3_compress(uint32_t digest[8], const uint8_t block[SM3_BLOCK_SIZE]);
    static void sm3_hmac_init(SM3_HMAC_CTX_t *ctx, const uint8_t *key, size_t key_len);
    static void sm3_hmac_update(SM3_HMAC_CTX_t *ctx, const uint8_t *data, size_t data_len);
    static void sm3_hmac_final(SM3_HMAC_CTX_t *ctx, uint8_t mac[SM3_HMAC_SIZE]);
    // bin to string
    static char *hexstr(uint8_t *buf, uint32_t len);
};

#endif //!_GMSM_SM3_H_