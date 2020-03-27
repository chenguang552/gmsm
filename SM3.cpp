#include "SM3.h"

//#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))
#define ROTATELEFT(X, n) (((X) << (n % 32)) | ((X) >> (32 - (n % 32))))

#define P0(x) ((x) ^ ROTATELEFT((x), 9) ^ ROTATELEFT((x), 17))
#define P1(x) ((x) ^ ROTATELEFT((x), 15) ^ ROTATELEFT((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

void SM3::sm3_init(SM3_CTX_t *ctx)

{
    ctx->digest[0] = 0x7380166F;
    ctx->digest[1] = 0x4914B2B9;
    ctx->digest[2] = 0x172442D7;
    ctx->digest[3] = 0xDA8A0600;
    ctx->digest[4] = 0xA96F30BC;
    ctx->digest[5] = 0x163138AA;
    ctx->digest[6] = 0xE38DEE4D;
    ctx->digest[7] = 0xB0FB0E4E;

    ctx->nblocks = 0;
    ctx->num = 0;
}

void SM3::sm3_update(SM3_CTX_t *ctx, const uint8_t *data, size_t data_len)
{
    if (ctx->num)
    {
        unsigned int left = SM3_BLOCK_SIZE - ctx->num;
        if (data_len < left)
        {
            memcpy(ctx->block + ctx->num, data, data_len);
            ctx->num += data_len;
            return;
        }
        else
        {
            memcpy(ctx->block + ctx->num, data, left);
            sm3_compress(ctx->digest, ctx->block);
            ctx->nblocks++;
            data += left;
            data_len -= left;
        }
    }
    while (data_len >= SM3_BLOCK_SIZE)
    {
        sm3_compress(ctx->digest, data);
        ctx->nblocks++;
        data += SM3_BLOCK_SIZE;
        data_len -= SM3_BLOCK_SIZE;
    }
    ctx->num = data_len;
    if (data_len)
    {
        memcpy(ctx->block, data, data_len);
    }
}

void SM3::sm3_final(SM3_CTX_t *ctx, uint8_t *digest)
{
    int i;
    uint32_t *pdigest = (uint32_t *)digest;
    uint32_t *count = (uint32_t *)(ctx->block + SM3_BLOCK_SIZE - 8);

    ctx->block[ctx->num] = 0x80;

    if (ctx->num + 9 <= SM3_BLOCK_SIZE)
    {
        memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
    }
    else
    {
        memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
        sm3_compress(ctx->digest, ctx->block);
        memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
    }

    count[0] = cpu_to_be32((ctx->nblocks) >> 23);
    count[1] = cpu_to_be32((ctx->nblocks << 9) + (ctx->num << 3));

    sm3_compress(ctx->digest, ctx->block);
    for (i = 0; i < sizeof(ctx->digest) / sizeof(ctx->digest[0]); i++)
    {
        pdigest[i] = cpu_to_be32(ctx->digest[i]);
    }
}

void SM3::sm3_compress(uint32_t digest[8], const uint8_t block[64])
{
    int j;
    uint32_t W[68], W1[64];
    const uint32_t *pblock = (const uint32_t *)block;

    uint32_t A = digest[0];
    uint32_t B = digest[1];
    uint32_t C = digest[2];
    uint32_t D = digest[3];
    uint32_t E = digest[4];
    uint32_t F = digest[5];
    uint32_t G = digest[6];
    uint32_t H = digest[7];
    uint32_t SS1, SS2, TT1, TT2, T[64];

    for (j = 0; j < 16; j++)
    {
        W[j] = cpu_to_be32(pblock[j]);
    }
    for (j = 16; j < 68; j++)
    {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTATELEFT(W[j - 3], 15)) ^ ROTATELEFT(W[j - 13], 7) ^ W[j - 6];
        ;
    }
    for (j = 0; j < 64; j++)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

    for (j = 0; j < 16; j++)
    {

        T[j] = 0x79CC4519;
        SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T[j], j)), 7);
        SS2 = SS1 ^ ROTATELEFT(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W1[j];
        TT2 = GG0(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTATELEFT(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTATELEFT(F, 19);
        F = E;
        E = P0(TT2);
    }

    for (j = 16; j < 64; j++)
    {

        T[j] = 0x7A879D8A;
        SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T[j], j)), 7);
        SS2 = SS1 ^ ROTATELEFT(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W1[j];
        TT2 = GG1(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTATELEFT(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTATELEFT(F, 19);
        F = E;
        E = P0(TT2);
    }

    digest[0] ^= A;
    digest[1] ^= B;
    digest[2] ^= C;
    digest[3] ^= D;
    digest[4] ^= E;
    digest[5] ^= F;
    digest[6] ^= G;
    digest[7] ^= H;
}

void SM3::sm3_sum(const uint8_t *msg, size_t msglen, uint8_t dgst[SM3_DIGEST_LENGTH])
{
    SM3_CTX_t ctx;

    sm3_init(&ctx);
    sm3_update(&ctx, msg, msglen);
    sm3_final(&ctx, dgst);

    memset(&ctx, 0, sizeof(SM3_CTX_t));
}

char *hexstr(uint8_t *buf, uint32_t len)
{
    const char *set = "0123456789abcdef";
    static char str[65], *tmp;
    unsigned char *end;
    if (len > 32)
        len = 32;
    end = buf + len;
    tmp = &str[0];
    while (buf < end)
    {
        *tmp++ = set[(*buf) >> 4];
        *tmp++ = set[(*buf) & 0xF];
        buf++;
    }
    *tmp = ' ';
    return str;
}

/**************************************************
*函数名称：SM3HashWithPreprocess
*功能: 计算 SM3 杂凑值（可能包含为满足 SM2 签名要求所做的预处理操作）
*参数:
 input[in]                         输入数据
 input_byte_len[in]                输入数据的字节长度
 public_key[in]                    签名者的公钥
 public_key_byte_len[in]           签名者公钥的字节长度
 signer_ID[in]                     签名者的 ID 值
 signer_ID_byte_len[in]            签名者 ID 的字节长度
 hash_value[out]                   SM3 杂凑值
 hash_value_byte_len_pointer[out]  指向表示 SM3 杂凑值字节长度变量的指针
*返回值:
    0    成功
    -1   失败
*备注：
   如果以下四个条件：
   a) 输入参数 public_key 是空指针；
   b) 输入参数 public_key_byte_len 的值等于 0；
   c) 输入参数 signer_ID 是空指针；
   d) 输入参数 signer_ID_byte_len 的值等于 0。
   中有一个成立，就直接计算输入数据 input 的 SM3 杂凑值，
   忽略输入参数 public_key, public_key_byte_len, signer_ID
   和 signer_ID_byte_len，这时不会进行 SM2 算法签名预处理
   操作。
   如果四个条件全部不成立，才执行 SM2 算法签名预处理操作，
   预处理计算过程遵循 GM/T 0009《 SM2 密码使用规范》。
**************************************************/

int SM3::SM3HashWithPreprocess(const uint8_t *input, uint32_t input_byte_len, uint8_t *public_key,
                               uint32_t public_key_byte_len, uint8_t *signer_ID,
                               uint32_t signer_ID_byte_len, uint8_t *hash_value,
                               uint32_t *hash_value_byte_len_pointer)
{
    unsigned short ID_bit_len;
    uint8_t *step1_input;
    uint32_t step1_input_byte_len;
    uint8_t step1_output[32];
    uint8_t *step2_input;
    uint32_t step2_input_byte_len;

    uint8_t a[32] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};

    uint8_t b[32] = {0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
                     0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
                     0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
                     0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0xE, 0x93};

    uint8_t x_G[32] = {0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
                       0x5F, 0x99, 0x4, 0x46, 0x6A, 0x39, 0xC9, 0x94,
                       0x8F, 0xE3, 0xB, 0xBF, 0xF2, 0x66, 0xB, 0xE1,
                       0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7};

    uint8_t y_G[32] = {0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
                       0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
                       0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
                       0x2, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0};

    // 下面定义的结构体 x 用于判断当前环境是 big-endian 还是 little-endian
    union {
        int i;
        char c[sizeof(int)];
    } x;

    if ((!public_key) || (!public_key_byte_len) || (!signer_ID) || (!signer_ID_byte_len))
    {
        sm3_sum(input, input_byte_len, hash_value);
        *hash_value_byte_len_pointer = 32U;
        return 0;
    }

    // 下面为满足 SM2 签名的要求，做预处理操作
    step1_input_byte_len = (2 + signer_ID_byte_len + 32 * 6);
    if (!(step1_input = (uint8_t *)malloc(step1_input_byte_len)))
    {
#ifdef _DEBUG
        printf("malloc function failed at %s, line %d!\n", __FILE__, __LINE__);
#endif
        return (-1);
    }
    memset(step1_input, 0, step1_input_byte_len);

    /* 预处理1 */
    ID_bit_len = (unsigned short)(signer_ID_byte_len * 8);

    /* 判断当前环境是 big-endian 还是 little-endian。
   国密规范中要求把 ENTL(用 2 个字节表示的 ID 的比特长度)
   以 big-endian 方式作为预处理 1 输入的前两个字节  */
    x.i = 1;
    if (x.c[0] == 1) /* little-endian */
    {
        memcpy(step1_input, (uint8_t *)(&ID_bit_len) + 1, 1);
        memcpy((step1_input + 1), (uint8_t *)(&ID_bit_len), 1);
    }
    else /* big-endian */
    {
        memcpy(step1_input, (uint8_t *)(&ID_bit_len), 1);
        memcpy((step1_input + 1), (uint8_t *)(&ID_bit_len) + 1, 1);
    }

    memcpy((step1_input + 2), signer_ID, signer_ID_byte_len);
    memcpy((step1_input + 2) + signer_ID_byte_len, a, 32);
    memcpy((step1_input + 2) + signer_ID_byte_len + 32, b, 32);
    memcpy((step1_input + 2 + signer_ID_byte_len + 64), x_G, 32);
    memcpy((step1_input + 2 + signer_ID_byte_len + 96), y_G, 32);
    //memcpy((step1_input + 2 + signer_ID_byte_len + 128), (public_key + 4 + 32), 32);
    // memcpy((step1_input + 2 + signer_ID_byte_len + 160), (public_key + 4 + 64 + 32), 32);
    memcpy((step1_input + 2 + signer_ID_byte_len + 128), (public_key + 1), 32);
    memcpy((step1_input + 2 + signer_ID_byte_len + 160), (public_key + 33), 32);

    sm3_sum(step1_input, step1_input_byte_len, step1_output);

    /* 预处理2 */
    step2_input_byte_len = (32 + input_byte_len);

    if (!(step2_input = (uint8_t *)malloc(step2_input_byte_len)))
    {
#ifdef _DEBUG
        printf("malloc function failed at %s, line %d!\n", __FILE__, __LINE__);
#endif
        free(step1_input);
        return (-1);
    }

    memcpy(step2_input, step1_output, 32);
    memcpy((step2_input + 32), input, input_byte_len);
    sm3_sum(step2_input, step2_input_byte_len, hash_value);
    *hash_value_byte_len_pointer = 32U;

    free(step1_input);
    free(step2_input);
    return 0;
}