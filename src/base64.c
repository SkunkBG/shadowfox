#include "base64.h"

static int sym_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;   /* '-' — URL-safe алфавит */
    if (c == '/' || c == '_') return 63;   /* '_' — URL-safe алфавит */
    return -1;
}

static int is_skippable(int c)
{
    return c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '=';
}

long base64_decode(const char *in, char *out, size_t out_size)
{
    if (!in || !out || out_size == 0) return -1;

    unsigned long acc  = 0;
    int           bits = 0;
    size_t        len  = 0;

    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (is_skippable(*p)) continue;

        int v = sym_val(*p);
        if (v < 0) return -1;

        acc   = (acc << 6) | (unsigned long)v;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (len + 1 >= out_size) return -1;
            out[len++] = (char)((acc >> bits) & 0xFF);
        }
    }

    out[len] = '\0';
    return (long)len;
}
