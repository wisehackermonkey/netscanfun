// icmp_sweep.c - ICMP ping sweep over an IPv4 range (requires root / CAP_NET_RAW)
//
// build:  gcc -std=gnu11 -O2 -Wall -Wextra -pthread -o icmp_sweep icmp_sweep.c
// usage:  sudo ./icmp_sweep <start_ip> <end_ip> [timeout_ms] [--no-dns] [--dns-threads N]
//         sudo ./icmp_sweep 126.235.0.1 to 126.235.170.163 1000
//
// the whole range is swept first, then reverse dns is done only for the hosts that
// answered, then the log is printed (progress goes to stderr).
//
// output (CSV, one line per IP, in order):
//   ip,ping_ms,icmp_type,icmp_code,ttl,status,hostname
//   (hostname = reverse dns of the probed ip, "-" if none / not looked up)
//
//   echo reply        : 126.235.0.1,12.345,0,0,52,reply
//   ICMP error reply  : 126.235.0.7,3.210,3,1,250,destination host unreachable
//   no answer at all  : 126.235.0.9,-1,-1,-1,unresponsive,timeout
//
// Only scan networks you own or are authorized to test.

#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <pthread.h>
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
    char * name;          // reverse dns name (malloc'd), NULL if none / not looked up
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

#define DEFAULT_DNS_THREADS 64
static int g_dns_threads = DEFAULT_DNS_THREADS; // 0 disables reverse dns (--no-dns)

// lookup the dns-name associated with an ip address (host byte order)
static bool reverse_dns_lookup(uint32_t ip_host_order, char * name_out, size_t size)
{
    struct sockaddr_in addr;
    zero_initialize(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip_host_order);

    char buffer[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&addr, sizeof(addr), buffer, sizeof(buffer), NULL, 0, NI_NAMEREQD) != 0)
    {
        return false;
    }
    snprintf(name_out, size, "%s", buffer);
    return true;
}

// ---------------------------------------------------------------------------
// reverse dns thread pool
//
// getnameinfo() blocks for as long as the resolver takes (up to seconds for a
// missing PTR record). Doing that one address at a time is by far the slowest
// part of a sweep, so a fixed set of worker threads pulls targets from a shared
// index and resolves them concurrently. Each job touches only its own
// target_t, so the only shared state is the job counter, protected by a mutex.
// ---------------------------------------------------------------------------
typedef struct
{
    pthread_t * threads;
    int thread_count;
    pthread_mutex_t lock;
    pthread_cond_t work_cv; // signalled when a new batch of jobs is available
    pthread_cond_t done_cv; // signalled when the last job of a batch finished
    target_t ** jobs;       // responders to resolve
    int count;              // number of jobs
    int next;               // next target to hand out
    int pending;            // jobs not finished yet
    bool shutdown;
} dns_pool_t;

static void * dns_worker(void * arg)
{
    dns_pool_t * pool = (dns_pool_t *)arg;

    pthread_mutex_lock(&pool->lock);
    for (;;)
    {
        while (!pool->shutdown && pool->next >= pool->count)
        {
            pthread_cond_wait(&pool->work_cv, &pool->lock);
        }
        if (pool->shutdown)
        {
            break;
        }

        target_t * t = pool->jobs[pool->next++];
        pthread_mutex_unlock(&pool->lock);

        // the slow part, runs without the lock held
        char name[NI_MAXHOST];
        if (reverse_dns_lookup(t->ip, name, sizeof(name)))
        {
            t->name = strdup(name);
        }

        pthread_mutex_lock(&pool->lock);
        if (--pool->pending == 0)
        {
            pthread_cond_signal(&pool->done_cv);
        }
    }
    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

static dns_pool_t * dns_pool_create(int thread_count)
{
    dns_pool_t * pool = calloc(1, sizeof(*pool));
    if (pool == NULL)
        return NULL;
    pool->threads = calloc((size_t)thread_count, sizeof(pthread_t));
    if (pool->threads == NULL)
    {
        free(pool);
        return NULL;
    }
    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->work_cv, NULL);
    pthread_cond_init(&pool->done_cv, NULL);

    for (int i = 0; i < thread_count; ++i)
    {
        if (pthread_create(&pool->threads[i], NULL, dns_worker, pool) != 0)
            break;
        ++pool->thread_count;
    }
    if (pool->thread_count == 0)
    {
        free(pool->threads);
        free(pool);
        return NULL;
    }
    return pool;
}

// resolve all given targets, blocks until every lookup is finished
static void dns_pool_run(dns_pool_t * pool, target_t ** jobs, int count)
{
    pthread_mutex_lock(&pool->lock);
    pool->jobs = jobs;
    pool->count = count;
    pool->next = 0;
    pool->pending = count;
    pthread_cond_broadcast(&pool->work_cv);
    while (pool->pending > 0)
    {
        pthread_cond_wait(&pool->done_cv, &pool->lock);
    }
    pool->jobs = NULL;
    pool->count = 0;
    pool->next = 0;
    pthread_mutex_unlock(&pool->lock);
}

static void dns_pool_destroy(dns_pool_t * pool)
{
    if (pool == NULL)
        return;
    pthread_mutex_lock(&pool->lock);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->work_cv);
    pthread_mutex_unlock(&pool->lock);
    for (int i = 0; i < pool->thread_count; ++i)
    {
        pthread_join(pool->threads[i], NULL);
    }
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->work_cv);
    pthread_cond_destroy(&pool->done_cv);
    free(pool->threads);
    free(pool);
}

static void print_result(const target_t * t)
{
    char ipstr[INET_ADDRSTRLEN];
    struct in_addr a;
    a.s_addr = htonl(t->ip);
    inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));

    // names were filled in by the dns thread pool (only hosts that answered
    // something are resolved, otherwise every silent address would cost a lookup)
    const char * name = t->name != NULL ? t->name : "-";

    if (!t->got_reply)
    {
        printf("%15s,        -1,-1,-1,unresponsive,timeout,%s\n", ipstr, name);
    }
    else
    {
        printf("%15s,%10.3f, %d, %d, %d, %s, %s\n", ipstr, t->ms, t->type, t->code, t->ttl,
               describe(t->type, t->code), name);
    }
}

// phase 1: ping one batch of addresses. 'targets' is this batch's slice of the result array.
static int run_batch(int fd, uint16_t id, uint32_t first_ip, target_t * targets, int count, int timeout_ms)
{
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
    // strip the options (--no-dns, --dns-threads N) out of argv
    for (int i = 1; i < argc;)
    {
        int remove_count = 0;
        if (strcmp(argv[i], "--no-dns") == 0)
        {
            g_dns_threads = 0;
            remove_count = 1;
        }
        else if (strcmp(argv[i], "--dns-threads") == 0)
        {
            if (i + 1 >= argc || atoi(argv[i + 1]) < 1)
            {
                fprintf(stderr, "--dns-threads needs a number >= 1\n");
                return 1;
            }
            g_dns_threads = atoi(argv[i + 1]);
            remove_count = 2;
        }
        if (remove_count == 0)
        {
            ++i;
            continue;
        }
        for (int j = i; j + remove_count < argc; ++j)
            argv[j] = argv[j + remove_count];
        argc -= remove_count;
    }

    // allow "start to end" as well as "start end"
    if (argc >= 4 && strcmp(argv[2], "to") == 0)
    {
        argv[2] = argv[1];
        argv++;
        argc--;
    }
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <start_ip> <end_ip> [timeout_ms] [--no-dns] [--dns-threads N]\n", argv[0]);
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

    // results for the whole range are kept in memory so the dns phase can run after the sweep
    const uint64_t total = (uint64_t)end - start + 1;
    target_t * targets = calloc(total, sizeof(target_t));
    if (targets == NULL)
    {
        fprintf(stderr, "not enough memory for %llu addresses, use a smaller range\n", (unsigned long long)total);
        close(fd);
        return 1;
    }

    // ---- phase 1: icmp sweep of the whole range ----
    for (uint64_t done = 0; done < total; done += BATCH_SIZE)
    {
        uint64_t remaining = total - done;
        int count = remaining < BATCH_SIZE ? (int)remaining : BATCH_SIZE;
        if (run_batch(fd, id, (uint32_t)(start + done), &targets[done], count, timeout_ms) != 0)
        {
            free(targets);
            close(fd);
            return 1;
        }
        fprintf(stderr, "swept %llu/%llu addresses\r", (unsigned long long)(done + count), (unsigned long long)total);
    }
    fprintf(stderr, "\n");
    close(fd);

    // ---- phase 2: reverse dns, only for the addresses that responded ----
    if (g_dns_threads > 0)
    {
        size_t responders = 0;
        for (uint64_t i = 0; i < total; ++i)
            if (targets[i].got_reply)
                ++responders;

        if (responders > 0)
        {
            target_t ** jobs = malloc(responders * sizeof(*jobs));
            if (jobs != NULL)
            {
                size_t n = 0;
                for (uint64_t i = 0; i < total; ++i)
                    if (targets[i].got_reply)
                        jobs[n++] = &targets[i];

                int thread_count = g_dns_threads;
                if ((size_t)thread_count > responders)
                    thread_count = (int)responders; // no point in more threads than lookups

                fprintf(stderr, "resolving %zu responding hosts with %d threads...\n", responders, thread_count);
                dns_pool_t * dns_pool = dns_pool_create(thread_count);
                if (dns_pool != NULL)
                {
                    dns_pool_run(dns_pool, jobs, (int)responders);
                    dns_pool_destroy(dns_pool);
                }
                else
                {
                    fprintf(stderr, "could not create dns thread pool, reverse dns skipped\n");
                }
                free(jobs);
            }
        }
    }

    // ---- phase 3: output, one line per ip in order ----
    printf("ip,ping_ms,icmp_type,icmp_code,ttl,status,hostname\n");
    for (uint64_t i = 0; i < total; ++i)
    {
        print_result(&targets[i]);
        free(targets[i].name);
    }
    fflush(stdout);
    free(targets);
    return 0;
}