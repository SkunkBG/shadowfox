#include "digest.h"

#include <string.h>

/* ---------- MD5 (RFC 1321) ---------- */

static unsigned rol32(unsigned x, int c) { return (x << c) | (x >> (32 - c)); }

static const unsigned char MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static const unsigned MD5_K[64] = {
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,
    0xa8304613u,0xfd469501u,0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,
    0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,0xf61e2562u,0xc040b340u,
    0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,
    0x676f02d9u,0x8d2a4c8au,0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,
    0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,0x289b7ec6u,0xeaa127fau,
    0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,
    0xffeff47du,0x85845dd1u,0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,
    0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
};

static void md5_block(unsigned h[4], const unsigned char *p)
{
    unsigned m[16];
    for (int i = 0; i < 16; i++)
        m[i] = (unsigned)p[i*4] | ((unsigned)p[i*4+1] << 8) |
               ((unsigned)p[i*4+2] << 16) | ((unsigned)p[i*4+3] << 24);

    unsigned a = h[0], b = h[1], c = h[2], d = h[3];

    for (int i = 0; i < 64; i++) {
        unsigned f;
        int      g;

        if (i < 16)      { f = (b & c) | (~b & d);          g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);          g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d;                   g = (3*i + 5) % 16; }
        else             { f = c ^ (b | ~d);                g = (7*i) % 16; }

        f += a + MD5_K[i] + m[g];
        a = d; d = c; c = b;
        b += rol32(f, MD5_S[i]);
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}

void md5(const void *data, size_t len, unsigned char out[16])
{
    unsigned h[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };

    const unsigned char *p = data;
    size_t whole = len / 64;

    for (size_t i = 0; i < whole; i++) md5_block(h, p + i * 64);

    unsigned char tail[128];
    size_t rest = len - whole * 64;
    memcpy(tail, p + whole * 64, rest);
    tail[rest++] = 0x80;

    size_t blocks = (rest + 8 > 64) ? 2 : 1;
    memset(tail + rest, 0, blocks * 64 - rest);

    unsigned long long bits = (unsigned long long)len * 8;
    for (int i = 0; i < 8; i++)
        tail[blocks * 64 - 8 + i] = (unsigned char)(bits >> (8 * i));

    for (size_t i = 0; i < blocks; i++) md5_block(h, tail + i * 64);

    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 4; b++)
            out[i*4 + b] = (unsigned char)(h[i] >> (8 * b));
}

/* ---------- SHA-256 (FIPS 180-4) ---------- */

static unsigned ror32(unsigned x, int c) { return (x >> c) | (x << (32 - c)); }

static const unsigned SHA_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha_block(unsigned h[8], const unsigned char *p)
{
    unsigned w[64];

    for (int i = 0; i < 16; i++)
        w[i] = ((unsigned)p[i*4] << 24) | ((unsigned)p[i*4+1] << 16) |
               ((unsigned)p[i*4+2] << 8) | (unsigned)p[i*4+3];

    for (int i = 16; i < 64; i++) {
        unsigned s0 = ror32(w[i-15], 7) ^ ror32(w[i-15], 18) ^ (w[i-15] >> 3);
        unsigned s1 = ror32(w[i-2], 17) ^ ror32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    unsigned a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];

    for (int i = 0; i < 64; i++) {
        unsigned S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        unsigned ch = (e & f) ^ (~e & g);
        unsigned t1 = hh + S1 + ch + SHA_K[i] + w[i];
        unsigned S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        unsigned mj = (a & b) ^ (a & c) ^ (b & c);
        unsigned t2 = S0 + mj;

        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

void sha256(const void *data, size_t len, unsigned char out[32])
{
    unsigned h[8] = { 0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                      0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u };

    const unsigned char *p = data;
    size_t whole = len / 64;

    for (size_t i = 0; i < whole; i++) sha_block(h, p + i * 64);

    unsigned char tail[128];
    size_t rest = len - whole * 64;
    memcpy(tail, p + whole * 64, rest);
    tail[rest++] = 0x80;

    size_t blocks = (rest + 8 > 64) ? 2 : 1;
    memset(tail + rest, 0, blocks * 64 - rest);

    unsigned long long bits = (unsigned long long)len * 8;
    for (int i = 0; i < 8; i++)
        tail[blocks * 64 - 1 - i] = (unsigned char)(bits >> (8 * i));

    for (size_t i = 0; i < blocks; i++) sha_block(h, tail + i * 64);

    for (int i = 0; i < 8; i++) {
        out[i*4]     = (unsigned char)(h[i] >> 24);
        out[i*4 + 1] = (unsigned char)(h[i] >> 16);
        out[i*4 + 2] = (unsigned char)(h[i] >> 8);
        out[i*4 + 3] = (unsigned char)h[i];
    }
}

void hex_encode(const unsigned char *src, size_t len, char *dst)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        dst[i*2]     = digits[src[i] >> 4];
        dst[i*2 + 1] = digits[src[i] & 0x0F];
    }
    dst[len * 2] = '\0';
}
