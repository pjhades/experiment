#include "test.h"
#include "../src/dns.c"

static uint8_t *make_question(char *name,
    uint16_t qtype, uint16_t qclass, size_t *len)
{
    size_t total = strlen(name) + 1 + sizeof(qtype) + sizeof(qclass);
    uint8_t *buf = malloc(total);
    if (!buf)
        return NULL;
    *len = total;

    char *p = name, *dot;
    uint8_t *b = buf;
    while ((dot = strchr(p, '.'))) {
        uint8_t label_len = dot - p;
        memcpy(b, &label_len, sizeof(label_len));
        memcpy(b + 1, p, label_len);
        b += sizeof(label_len) + label_len;
        p = dot + 1;
    }
    memcpy(b, (uint8_t[]){0}, 1);
    b++;
    memcpy(b, &qtype, sizeof(qtype));
    b += sizeof(qtype);
    memcpy(b, &qclass, sizeof(qclass));
    return buf;
}

static bool test_parse_good_question(void)
{
    uint8_t *raw, *p;
    size_t len, left;
    struct dns_question question;

    raw = make_question("www.wikipedia.org.", 0xabcd, 0x1234, &len);
    p = raw;
    left = len;
    ASSERT(parse_question(&p, &left, &question));
    ASSERT(left == 0);
    ASSERT(question.qname == raw);
    ASSERT(question.qname_len == 19);
    ASSERT(question.vals->qtype == 0xcdab);
    ASSERT(question.vals->qclass == 0x3412);
    free(raw);
    return true;
}

static bool test_parse_bad_question(void)
{
    {
        /* too short name */
        uint8_t raw[] = {3, 'w', 'w', 'w'};
        size_t left = 4;
        struct dns_question question;
        uint8_t *p = raw;
        ASSERT(!parse_question(&p, &left, &question));
    }

    {
        /* too long name */
        char *label = "abc";
        size_t label_len = strlen(label),
               repeat = 100,
               len = (1 + strlen(label)) * 100 + 1;
        ASSERT(label_len == 3);
        ASSERT(len > DNS_NAME_MAX_LEN);
        ASSERT(len == 401);

        uint8_t *raw = malloc(len);
        if (!raw)
            return NULL;

        uint8_t *b = raw;
        for (size_t i = 0; i < repeat; i++) {
            memcpy(b, (uint8_t[]){label_len}, 1);
            memcpy(b + 1, label, label_len);
            b += 1 + label_len;
        }
        memcpy(b, (uint8_t[]){0}, 1);

        size_t left = len;
        struct dns_question question;
        uint8_t *p = raw;
        ASSERT(!parse_question(&p, &left, &question));
    }

    {
        /* no qtype or qclass*/
        uint8_t *raw;
        size_t len;
        struct dns_question question;
        raw = make_question("www.wikipedia.org.", 0xabcd, 0x1234, &len);
        len -= 2;
        ASSERT(!parse_question(&raw, &len, &question));
        free(raw);
        return true;
    }

    return true;
}

static bool test_parse_good_header(void)
{
    struct dns_header header = {
        .id = 0xbeef,
        .flags = 0xfade,
        .qdcount = 0x1234,
        .ancount = 0xdeed,
        .nscount = 0xbead,
        .arcount = 0x5678,
    };
    struct dns_header *parsed;
    uint8_t *raw = (uint8_t *)&header, *p = raw;
    size_t len = sizeof(header);
    ASSERT(parse_header(&p, &len, &parsed));
    ASSERT(len == 0);
    ASSERT(parsed->id == 0xefbe);
    ASSERT(parsed->flags == 0xdefa);
    ASSERT(parsed->qdcount == 0x3412);
    ASSERT(parsed->ancount == 0xedde);
    ASSERT(parsed->nscount == 0xadbe);
    ASSERT(parsed->arcount == 0x7856);
    return true;
}

static bool test_parse_bad_header(void)
{
    uint8_t raw[] = {1, 2, 3, 4, 5, 6, 7}, *p = raw;
    size_t len = sizeof(raw);
    struct dns_header *parsed;
    ASSERT(!parse_header(&p, &len, &parsed));
    return true;
}

int main(void)
{
    RUN_TEST(test_parse_good_question);
    RUN_TEST(test_parse_bad_question);
    RUN_TEST(test_parse_good_header);
    RUN_TEST(test_parse_bad_header);
    return 0;
}
