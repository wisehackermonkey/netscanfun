// icmp_sweep.c - ICMP ping sweep over an IPv4 range (requires root / CAP_NET_RAW)
//
// build:  gcc -std=gnu11 -O2 -Wall -Wextra -o icmp_sweep icmp_sweep.c
// usage:  sudo ./icmp_sweep <start_ip> <end_ip> [timeout_ms]
//         sudo ./icmp_sweep 126.235.0.1 to 126.235.170.163 1000
//
// output (CSV, one line per IP, in order):
//   ip,ping_ms,icmp_type,icmp_code,ttl,status
//
//   echo reply        : 126.235.0.1,12.345,0,0,52,reply
//   ICMP error reply  : 126.235.0.7,3.210,3,1,250,destination host unreachable
//   no answer at all  : 126.235.0.9,-1,-1,-1,unresponsive,timeout
//
// Only scan networks you own or are authorized to test.

#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define ICMP_PAYLOAD_LENGTH 56
// #define BATCH_SIZE 512 // addresses in flight at once (must be <= 65536 for the 16-bit sequence)
#define BATCH_SIZE 65536 // addresses in flight at once (must be <= 65536 for the 16-bit sequence)

struct ping_pkt
{
    struct icmphdr hdr;
    char payload[ICMP_PAYLOAD_LENGTH];
};

typedef struct
{
    uint32_t ip;          // host byte order
    bool done;
    bool got_reply;       // true if anything (echo reply or ICMP error) came back
    double ms;
    int type;
    int code;
    int ttl;
    struct timespec sent;
} target_t;

static void zero_initialize(void * data, size_t size)
{
    memset(data, 0, size);
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static double get_difference_ms(const struct timespec * t1, const struct timespec * t2)
{
    double ns = (t2->tv_nsec - t1->tv_nsec) / 1000000.0;
    double ms = (t2->tv_sec - t1->tv_sec) * 1000.0;
    return ms + ns;
}

// standard internet checksum (RFC 1071). checksum field must be 0 when called.
static unsigned short calculate_checksum(const void * data, size_t size)
{
    const unsigned char * p = (const unsigned char *)data;
    uint32_t sum = 0;
    for (; size > 1; size -= 2, p += 2)
    {
        sum += (uint32_t)(p[0] | (p[1] << 8)); // native-endian 16 bit words, result stays valid
    }
    if (size == 1)
    {
        sum += *p;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

static void build_echo_request(struct ping_pkt * pkt, uint16_t id, uint16_t seq)
{
    zero_initialize(pkt, sizeof(*pkt));
    pkt->hdr.type = ICMP_ECHO;
    pkt->hdr.code = 0;
    pkt->hdr.un.echo.id = htons(id);
    pkt->hdr.un.echo.sequence = htons(seq);
    for (size_t i = 0; i < ICMP_PAYLOAD_LENGTH; ++i)
    {
        pkt->payload[i] = (char)('0' + (i % 64));
    }
    // checksum must be calculated _after_ everything else is filled in
    pkt->hdr.checksum = 0;
    pkt->hdr.checksum = calculate_checksum(pkt, sizeof(*pkt));
}

static const char * describe(int type, int code)
{
    switch (type)
    {
    case ICMP_ECHOREPLY:
        return "reply";
    case ICMP_DEST_UNREACH:
        switch (code)
        {
        case ICMP_NET_UNREACH:    return "destination network unreachable";
        case ICMP_HOST_UNREACH:   return "destination host unreachable";
        case ICMP_PROT_UNREACH:   return "destination protocol unreachable";
        case ICMP_PORT_UNREACH:   return "destination port unreachable";
        case ICMP_FRAG_NEEDED:    return "fragmentation needed";
        case ICMP_SR_FAILED:      return "source route failed";
        case ICMP_NET_UNKNOWN:    return "destination network unknown";
        case ICMP_HOST_UNKNOWN:   return "destination host unknown";
        case ICMP_NET_ANO:        return "network administratively prohibited";
        case ICMP_HOST_ANO:       return "host administratively prohibited";
        case ICMP_PKT_FILTERED:   return "communication administratively prohibited";
        default:                  return "destination unreachable";
        }
    case ICMP_SOURCE_QUENCH:  return "source quench";
    case ICMP_REDIRECT:       return "redirect";
    case ICMP_TIME_EXCEEDED:  return code == 0 ? "ttl exceeded in transit" : "fragment reassembly time exceeded";
    case ICMP_PARAMETERPROB:  return "parameter problem";
    default:                  return "other icmp message";
    }
}

// look at one received datagram (IP header + ICMP) and, if it belongs to one of
// our outstanding probes, record the result.
static void handle_packet(const uint8_t * buf, ssize_t len, target_t * targets, int count, uint16_t id)
{
    if (len < (ssize_t)sizeof(struct ip))
        return;
    const struct ip * ip = (const struct ip *)buf;
    size_t ihl = (size_t)ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_ICMP || len < (ssize_t)(ihl + sizeof(struct icmphdr)))
        return;

    const struct icmphdr * icmp = (const struct icmphdr *)(buf + ihl);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (icmp->type == ICMP_ECHOREPLY)
    {
        if (ntohs(icmp->un.echo.id) != id)
            return;
        unsigned seq = ntohs(icmp->un.echo.sequence);
        if ((int)seq >= count)
            return;
        target_t * t = &targets[seq];
        if (t->done || ntohl(ip->ip_src.s_addr) != t->ip)
            return;
        t->done = t->got_reply = true;
        t->ms = get_difference_ms(&t->sent, &now);
        t->type = ICMP_ECHOREPLY;
        t->code = icmp->code;
        t->ttl = ip->ip_ttl;
        return;
    }

    if (icmp->type == ICMP_DEST_UNREACH || icmp->type == ICMP_TIME_EXCEEDED ||
        icmp->type == ICMP_SOURCE_QUENCH || icmp->type == ICMP_REDIRECT ||
        icmp->type == ICMP_PARAMETERPROB)
    {
        // error messages carry the original IP header + first 8 bytes of our echo request
        size_t off = ihl + 8;
        if (len < (ssize_t)(off + sizeof(struct ip)))
            return;
        const struct ip * inner_ip = (const struct ip *)(buf + off);
        size_t inner_ihl = (size_t)inner_ip->ip_hl * 4;
        if (inner_ip->ip_p != IPPROTO_ICMP || len < (ssize_t)(off + inner_ihl + 8))
            return;
        const struct icmphdr * orig = (const struct icmphdr *)(buf + off + inner_ihl);
        if (orig->type != ICMP_ECHO || ntohs(orig->un.echo.id) != id)
            return;
        unsigned seq = ntohs(orig->un.echo.sequence);
        if ((int)seq >= count)
            return;
        target_t * t = &targets[seq];
        if (t->done || ntohl(inner_ip->ip_dst.s_addr) != t->ip)
            return;
        t->done = t->got_reply = true;
        t->ms = get_difference_ms(&t->sent, &now);
        t->type = icmp->type;
        t->code = icmp->code;
        t->ttl = ip->ip_ttl; // ttl of the router/host that sent the error
    }
}

static void print_result(const target_t * t)
{
    char ipstr[INET_ADDRSTRLEN];
    struct in_addr a;
    a.s_addr = htonl(t->ip);
    inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));

    if (!t->got_reply)
    {
        printf("%15s,        -1,-1,-1,unresponsive,timeout\n", ipstr);
    }
    else
    {
        printf("%15s,%10.3f, %d, %d, %d, %s\n", ipstr, t->ms, t->type, t->code, t->ttl, describe(t->type, t->code));
    }
}

static int run_batch(int fd, uint16_t id, uint32_t first_ip, int count, int timeout_ms)
{
    target_t targets[BATCH_SIZE];
    zero_initialize(targets, sizeof(targets));

    // send everything in the batch
    for (int i = 0; i < count; ++i)
    {
        target_t * t = &targets[i];
        t->ip = first_ip + (uint32_t)i;

        struct ping_pkt pkt;
        build_echo_request(&pkt, id, (uint16_t)i);

        struct sockaddr_in dst;
        zero_initialize(&dst, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(t->ip);

        clock_gettime(CLOCK_MONOTONIC, &t->sent);
        if (sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
        {
            // local failure (e.g. network unreachable): report as unresponsive
            t->done = true;
        }
    }

    // collect replies until all answered or the timeout (counted from the last send) expires
    double deadline = now_ms() + timeout_ms;
    int outstanding = 0;
    for (int i = 0; i < count; ++i)
        if (!targets[i].done)
            ++outstanding;

    while (outstanding > 0)
    {
        double remaining = deadline - now_ms();
        if (remaining <= 0)
            break;

        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int pr = poll(&pfd, 1, (int)remaining + 1);
        if (pr < 0)
        {
            if (errno == EINTR)
                continue;
            perror("poll");
            return -1;
        }
        if (pr == 0)
            break;

        // drain everything currently queued
        for (;;)
        {
            uint8_t buf[2048];
            ssize_t n = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
            if (n < 0)
                break;
            handle_packet(buf, n, targets, count, id);
        }

        outstanding = 0;
        for (int i = 0; i < count; ++i)
            if (!targets[i].done)
                ++outstanding;
    }

    for (int i = 0; i < count; ++i)
        print_result(&targets[i]);
    fflush(stdout);
    return 0;
}

static bool parse_ip(const char * s, uint32_t * out)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1)
        return false;
    *out = ntohl(a.s_addr);
    return true;
}

int main(int argc, char * argv[])
{
    // allow "start to end" as well as "start end"
    if (argc >= 4 && strcmp(argv[2], "to") == 0)
    {
        argv[2] = argv[1];
        argv++;
        argc--;
    }
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <start_ip> <end_ip> [timeout_ms]\n", argv[0]);
        return 1;
    }

    uint32_t start, end;
    if (!parse_ip(argv[1], &start) || !parse_ip(argv[2], &end))
    {
        fprintf(stderr, "invalid ip address\n");
        return 1;
    }
    if (start > end)
    {
        fprintf(stderr, "start ip must not be greater than end ip\n");
        return 1;
    }
    int timeout_ms = argc >= 4 ? atoi(argv[3]) : 1000;
    if (timeout_ms <= 0)
        timeout_ms = 1000;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
    {
        perror("socket (raw icmp requires root or CAP_NET_RAW)");
        return 1;
    }

    const uint16_t id = (uint16_t)getpid();
    printf("ip,ping_ms,icmp_type,icmp_code,ttl,status\n");

    for (uint64_t ip = start; ip <= end; ip += BATCH_SIZE)
    {
        uint64_t remaining = (uint64_t)end - ip + 1;
        int count = remaining < BATCH_SIZE ? (int)remaining : BATCH_SIZE;
        if (run_batch(fd, id, (uint32_t)ip, count, timeout_ms) != 0)
            break;
    }

    close(fd);
    return 0;
}