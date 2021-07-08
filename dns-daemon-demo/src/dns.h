#pragma once

#include <assert.h>

#define DNS_PORT_STR "53"

enum {
    /* https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4 */
    DNS_NAME_MAX_LEN = 255,
    DNS_LABEL_MAX_LEN = 63,
    DNS_MSG_MAX_LEN = 512,
};

/* https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1 */
#define DNS_FLAGS_QR     0x8000
#define DNS_FLAGS_OPCODE 0x7800
#define DNS_FLAGS_AA     0x0400
#define DNS_FLAGS_TC     0x0200
#define DNS_FLAGS_RD     0x0100
#define DNS_FLAGS_RA     0x0080
#define DNS_FLAGS_Z      0x0070
#define DNS_FLAGS_RCODE  0x000f

enum dns_opcode {
    DNS_OPCODE_QUERY = 0,
};

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

_Static_assert(sizeof(struct dns_header) == 12,
               "dns_header should be 12 bytes");

/* https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2 */
enum dns_type {
    DNS_TYPE_A = 1,
};

_Static_assert(sizeof(enum dns_type) >= sizeof(uint16_t),
               "dns_type should be at least 2 bytes");

/* https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4 */
enum dns_class {
    DNS_CLASS_IN = 1,
};

_Static_assert(sizeof(enum dns_class) >= sizeof(uint16_t),
               "dns_class should be at least 2 bytes");

struct dns_question_values {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((packed));

struct dns_question {
    uint8_t *qname;
    uint8_t qname_len;
    struct dns_question_values *vals;
};

struct dns_rr_values {
    uint16_t type;
    uint16_t klass;
    uint32_t ttl;
    uint16_t rdlength;
} __attribute__((packed));

struct dns_rr {
    uint8_t name[DNS_NAME_MAX_LEN];
    uint8_t name_len;
    struct dns_rr_values vals;
    union {
        uint32_t a;
    } rdata;
};

struct dns_message {
    struct dns_header *header;
    struct dns_question question;
    struct dns_rr rr;
};

bool dns_parse_request(uint8_t *raw, size_t len, struct dns_message *req);
void dns_make_response(struct dns_message *packet);
