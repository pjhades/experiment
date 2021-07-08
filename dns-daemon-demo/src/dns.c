#include "common.h"
#include "log.h"
#include "dns.h"
#include <arpa/inet.h>
#include <string.h>

static bool parse_question(uint8_t **raw, size_t *len,
    struct dns_question *question)
{
    uint8_t *p = *raw, *end = p + *len;
    /* scan qname */
    while (p < end && *p != 0)
        p += *p + 1;
    if (p >= end)
        return false;
    p++;

    if (p - *raw > DNS_NAME_MAX_LEN)
        return false;
    question->qname = *raw;
    question->qname_len = p - *raw;

    /* scan qtype and qclass */
    if (p + sizeof(struct dns_question_values) > end)
        return false;
    question->vals = (struct dns_question_values *)p;
    question->vals->qtype = ntohs(question->vals->qtype);
    question->vals->qclass = ntohs(question->vals->qclass);

    size_t nparsed = question->qname_len + sizeof(struct dns_question_values);
    *raw += nparsed;
    *len -= nparsed;
    return true;
}

static bool parse_header(uint8_t **raw, size_t *len,
    struct dns_header **header)
{
    if (*len < sizeof(struct dns_header))
        return false;

    struct dns_header *hdr = (struct dns_header *)*raw;
    hdr->id = ntohs(hdr->id);
    hdr->flags = ntohs(hdr->flags);
    hdr->qdcount = ntohs(hdr->qdcount);
    hdr->ancount = ntohs(hdr->ancount);
    hdr->nscount = ntohs(hdr->nscount);
    hdr->arcount = ntohs(hdr->arcount);
    *header = hdr;

    *raw += sizeof(struct dns_header);
    *len -= sizeof(struct dns_header);

    return true;
}

static bool check_header(struct dns_header *header)
{
    if ((header->flags & DNS_FLAGS_QR) != 0) {
        log_dbg("request dropped: expect a request but received a response");
        return false;
    }

    if (header->qdcount > 1) {
        log_dbg("request dropped: multi-question is not supported");
        return false;
    }
    else if (header->qdcount == 0) {
        log_dbg("request dropped: no question in request");
        return false;
    }

    if (((header->flags & DNS_FLAGS_OPCODE) >> 11) != DNS_OPCODE_QUERY) {
        log_dbg("request dropped: opcode is not supported");
        return false;
    }
    if ((header->flags & DNS_FLAGS_TC) != 0) {
        log_dbg("request dropped: request is truncated");
        return false;
    }

    return true;
}

static bool check_question(struct dns_question *question)
{
    if (question->vals->qtype != DNS_TYPE_A ||
        question->vals->qclass != DNS_CLASS_IN) {
        log_dbg("request dropped: question type or class is not supported");
        return false;
    }
    return true;
}

bool dns_parse_request(uint8_t *raw, size_t len, struct dns_message *req)
{
    uint8_t *pos = raw;
    size_t left = len;

    if (!parse_header(&pos, &left, &req->header)) {
        log_dbg("fail to parse header");
        return false;
    }
    if (!check_header(req->header))
        return false;
    if (!parse_question(&pos, &left, &req->question)) {
        log_dbg("fail to parse question");
        return false;
    }
    if (!check_question(&req->question))
        return false;

    return true;
}

void dns_make_response(struct dns_message *packet)
{
    packet->header->flags |= DNS_FLAGS_QR;
    packet->header->flags &= ~DNS_FLAGS_AA;
    packet->header->flags &= ~DNS_FLAGS_TC;
    packet->header->flags |= DNS_FLAGS_RA;
    packet->header->flags &= ~DNS_FLAGS_Z;
    packet->header->flags &= ~DNS_FLAGS_RCODE;
    packet->header->flags = htons(packet->header->flags);

    packet->header->id = htons(packet->header->id);
    packet->header->qdcount = htons(packet->header->qdcount);
    packet->header->ancount = htons(1);
    packet->header->nscount = 0;
    packet->header->arcount = 0;

    packet->question.vals->qtype = htons(packet->question.vals->qtype);
    packet->question.vals->qclass = htons(packet->question.vals->qclass);

    uint16_t name_ptr = htons(0xc000 | sizeof(struct dns_header));
    memcpy(packet->rr.name, &name_ptr, sizeof(name_ptr));
    packet->rr.name_len = sizeof(name_ptr);
    packet->rr.vals = (struct dns_rr_values){
        .type = htons(DNS_TYPE_A),
        .klass = htons(DNS_CLASS_IN),
        .ttl = htonl(3600),
        .rdlength = htons(sizeof(uint32_t)),
    };
    packet->rr.rdata.a = htonl((1<<24) | (2<<16) | (3<<8) | 4);
}
