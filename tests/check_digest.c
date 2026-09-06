/* Хеши против опубликованных векторов. Своя реализация без сверки с
   эталоном бессмысленна: ошибка в ней проявится как «пароль не подходит»
   и будет искаться где угодно, только не здесь. */
#include "digest.h"
#include "shadowfox.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...)                                     \
    do {                                                     \
        if (!(cond)) {                                       \
            printf("  ПРОВАЛ %s:%d: ", __FILE__, __LINE__);  \
            printf(__VA_ARGS__);                             \
            printf("\n");                                    \
            failures++;                                      \
        }                                                    \
    } while (0)

static void check_md5(const char *in, const char *want)
{
    unsigned char d[16];
    char          hex[33];

    md5(in, strlen(in), d);
    hex_encode(d, sizeof(d), hex);
    CHECK(!strcmp(hex, want), "md5(\"%s\") = %s, ждали %s", in, hex, want);
}

static void check_sha(const char *in, const char *want)
{
    unsigned char d[32];
    char          hex[65];

    sha256(in, strlen(in), d);
    hex_encode(d, sizeof(d), hex);
    CHECK(!strcmp(hex, want), "sha256(\"%s\") = %s, ждали %s", in, hex, want);
}

int main(void)
{
    printf("check_digest " VERSION "\n");

    /* RFC 1321, приложение A.5. */
    check_md5("", "d41d8cd98f00b204e9800998ecf8427e");
    check_md5("a", "0cc175b9c0f1b6a831c399e269772661");
    check_md5("abc", "900150983cd24fb0d6963f7d28e17f72");
    check_md5("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
    check_md5("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
    check_md5("12345678901234567890123456789012345678901234567890"
              "123456789012345678901234567890",
              "57edf4a22be3c955ac49da2e2107b67a");

    /* Граница блока. 55 байт — последний размер, влезающий с длиной в
       один блок; 56 требует второго; 64 — ровно блок. Наивная набивка
       ломается именно здесь, а на коротких строках выглядит рабочей. */
    check_md5("1234567890123456789012345678901234567890123456789012345",
              "c9ccf168914a1bcfc3229f1948e67da0");
    check_md5("12345678901234567890123456789012345678901234567890123456",
              "49f193adce178490e34d1b3a4ec0064c");
    check_md5("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "b06521f39153d618550606be297466d5");
    check_md5("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "014842d480b571495a4a0363793f7367");
    check_md5("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "c743a45e0d2e6a95cb859adae0248435");

    /* FIPS 180-4. */
    check_sha("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_sha("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    check_sha("1234567890123456789012345678901234567890123456789012345",
              "03c3a70e99ed5eeccd80f73771fcf1ece643d939d9ecc76f25544b0233f708e9");
    check_sha("12345678901234567890123456789012345678901234567890123456",
              "0be66ce72c2467e793202906000672306661791622e0ca9adf4a8955b2ed189c");
    check_sha("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    check_sha("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0");

    if (failures) {
        printf("ПРОВАЛЕНО проверок: %d\n", failures);
        return 1;
    }
    printf("все проверки пройдены\n");
    return 0;
}
