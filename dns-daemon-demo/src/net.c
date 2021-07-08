#include "common.h"
#include "log.h"
#include "dns.h"
#include <netdb.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

enum {
    /* These numbers are very arbitrary and should be
     * benchmarked in practical situations. */
    RECV_BATCH = 1024,
    MAX_RETRY = 3,
};

void udp_open(struct config *conf)
{
    struct addrinfo *res, hint = {
        .ai_flags = AI_NUMERICSERV | AI_PASSIVE,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = 0,
    };

    int ret = getaddrinfo(NULL, conf->port, &hint, &res);
    if (ret != 0)
        errx(EXIT_FAILURE, "getaddrinfo: %s", gai_strerror(ret));

    int sock = -1;
    for (struct addrinfo *info = res; info; info = info->ai_next) {
        sock = socket(info->ai_family,
                      info->ai_socktype,
                      info->ai_protocol);
        if (sock == -1)
            err(EXIT_FAILURE, "socket");
        if (bind(sock, info->ai_addr, info->ai_addrlen) == -1) {
            close(sock);
            err(EXIT_FAILURE, "bind");
        }
        break;
    }
    if (sock == -1)
        errx(EXIT_FAILURE, "fail to get a socket");

    conf->sock = sock;
    freeaddrinfo(res);
}

struct msg_context {
    uint8_t raw[DNS_MSG_MAX_LEN];
    struct sockaddr_in addr;
} ctx[RECV_BATCH];

static bool handle_request(int sock, struct msg_context *ctx, size_t len)
{
    struct dns_message packet;
    if (!dns_parse_request(ctx->raw, len, &packet))
        return false;

    log_dbg("id=%04x opcode=%x aa=%x tc=%x rd=%d ra=%x qdcount=%u",
            packet.header->id,
            (packet.header->flags & DNS_FLAGS_OPCODE) >> 11,
            (packet.header->flags & DNS_FLAGS_AA) >> 10,
            (packet.header->flags & DNS_FLAGS_TC) >> 9,
            (packet.header->flags & DNS_FLAGS_RD) >> 8,
            (packet.header->flags & DNS_FLAGS_RA) >> 7,
            packet.header->qdcount);

    dns_make_response(&packet);

    struct iovec iovs[] = {
        {
            .iov_base = packet.header,
            .iov_len = sizeof(struct dns_header),
        },
        {
            .iov_base = packet.question.qname,
            .iov_len = packet.question.qname_len,
        },
        {
            .iov_base = packet.question.vals,
            .iov_len = sizeof(struct dns_question_values),
        },
        {
            .iov_base = packet.rr.name,
            .iov_len = packet.rr.name_len,
        },
        {
            .iov_base = &packet.rr.vals,
            .iov_len = sizeof(struct dns_rr_values),
        },
        {
            .iov_base = &packet.rr.rdata.a,
            .iov_len = sizeof(uint32_t),
        },
    };

    size_t niovs = sizeof(iovs) / sizeof(iovs[0]);
    struct msghdr mh = {
        .msg_name = &ctx->addr,
        .msg_namelen = sizeof(ctx->addr),
        .msg_iov = iovs,
        .msg_iovlen = niovs,
    };
    size_t nretry = 0, resp_size = 0;
    long nsec = 1;

    for (size_t i = 0; i < niovs; i++)
        resp_size += iovs[i].iov_len;

    do {
        ssize_t nsend = sendmsg(sock, &mh, MSG_DONTWAIT);
        if (nsend == -1
            && errno != EINTR
            && errno != EAGAIN
            && errno != EWOULDBLOCK) {
            log_perr("sendmsg");
            return false;
        }
        else if (nsend != -1)
            return true;

        struct timespec duration = { .tv_nsec = nsec };
        nanosleep(&duration, NULL);
        nsec *= 2;
    } while (++nretry < MAX_RETRY);

    log_err("fail to send response");
    return false;
}

void net_loop(struct config *conf)
{
    struct mmsghdr msgs[RECV_BATCH] = {0};
    struct iovec   iovs[RECV_BATCH] = {0};

    for (int i = 0; i < RECV_BATCH; i++) {
        iovs[i].iov_base = ctx[i].raw;
        iovs[i].iov_len = sizeof(ctx[i].raw);

        msgs[i].msg_hdr.msg_name = &ctx[i].addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(ctx[i].addr);
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    log_info("listening on UDP port %s", conf->port);

    for (;;) {
        int nmsg = recvmmsg(conf->sock, msgs, RECV_BATCH, MSG_WAITFORONE, NULL);
        if (nmsg == -1) {
            log_perr("recvmmsg");
            break;
        }
        for (int i = 0; i < nmsg; i++)
            handle_request(conf->sock, &ctx[i], msgs[i].msg_len);
    }
}
