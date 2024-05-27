/*
 * Copyright (c) 2008,2009,2010,2011  Yahoo! Inc.  All rights reserved.
 *
 * Redistribution and use of this software in source and binary forms,
 * with or without modification, are permitted provided that the following
 * conditions are met:
 *
 * * Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other
 *   materials provided with the distribution.
 *
 * * Neither the name of Yahoo! Inc. nor the names of its
 *   contributors may be used to endorse or promote products
 *   derived from this software without specific prior
 *   written permission of Yahoo! Inc.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/pfil.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>

#ifdef PFIL_VERSION
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
static pfil_hook_t pfh_hook_inet;
static pfil_hook_t pfh_hook_inet6;
#endif

static int
dscp_rewrite_inet_aton(const char *cp, struct in_addr *addr)
{
        u_long octets[4];
        const char *c;
        char *end;
        int i;

        i = 0;
        c = cp;
        for (;;)
        {
                octets[i] = strtoul(c, &end, 10);
                if (c == end)
                        /* Unable to parse an octet. */
                        return (EINVAL);

                /* Parsed the whole string? */
                if (*end == '\0')
                        break;

                /* Next octet? */
                if (*end == '.')
                {
                        if (i == 3)
                                /* Too many octets. */
                                return (EINVAL);
                        c = end + 1;
                        i++;
                }
                else
                        /* Invalid character. */
                        return (EINVAL);
        }

        if (i != 3)
                /* Not enough octets. */
                return (EINVAL);

        /* Range-check all the octets. */
        for (i = 0; i < 4; i++)
                if (octets[i] > 0xff)
                        return (EINVAL);

        addr->s_addr = htonl(octets[0] << 24 | octets[1] << 16 |
                             octets[2] << 8 | octets[3]);
        return (0);
}

SYSCTL_NODE(_net_inet_ip, OID_AUTO, dscp_rewrite, CTLFLAG_RD, NULL,
            "DSCP rewrite configuration");

static int dscp_rewrite_enabled = 1;
SYSCTL_INT(_net_inet_ip_dscp_rewrite, OID_AUTO, enabled, CTLFLAG_RW,
           &dscp_rewrite_enabled, 0, "DSCP rewrite enabled");

static int dscp_rewrite_debug = 0;
SYSCTL_INT(_net_inet_ip_dscp_rewrite, OID_AUTO, debug, CTLFLAG_RW,
           &dscp_rewrite_debug, 0, "DSCP rewrite debug log");

static struct in_addr rewrite_addresses[64];
static struct in6_addr rewrite_addresses6[64];

static int
rewrite_sysctl_handler(SYSCTL_HANDLER_ARGS)
{
        char buf[24];
        int error;

        inet_ntoa_r(rewrite_addresses[arg2], buf);
        error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
        if (error)
                return (error);
        error = dscp_rewrite_inet_aton(buf, &rewrite_addresses[arg2]);
        return (error);
}

SYSCTL_NODE(_net_inet_ip_dscp_rewrite, OID_AUTO, ip4, CTLFLAG_RD, NULL,
            "DSCP rewrite source IPv4 addresses");

#define DSCP_SYSCTL(index)                                         \
        SYSCTL_PROC(_net_inet_ip_dscp_rewrite_ip4, (index), index, \
                    CTLTYPE_STRING | CTLFLAG_RW, NULL, (index),    \
                    rewrite_sysctl_handler, "A", "DSCP " #index " source IPv4")

DSCP_SYSCTL(1);
DSCP_SYSCTL(2);
DSCP_SYSCTL(3);
DSCP_SYSCTL(4);
DSCP_SYSCTL(5);
DSCP_SYSCTL(6);
DSCP_SYSCTL(7);
DSCP_SYSCTL(8);
DSCP_SYSCTL(9);
DSCP_SYSCTL(10);
DSCP_SYSCTL(11);
DSCP_SYSCTL(12);
DSCP_SYSCTL(13);
DSCP_SYSCTL(14);
DSCP_SYSCTL(15);
DSCP_SYSCTL(16);
DSCP_SYSCTL(17);
DSCP_SYSCTL(18);
DSCP_SYSCTL(19);
DSCP_SYSCTL(20);
DSCP_SYSCTL(21);
DSCP_SYSCTL(22);
DSCP_SYSCTL(23);
DSCP_SYSCTL(24);
DSCP_SYSCTL(25);
DSCP_SYSCTL(26);
DSCP_SYSCTL(27);
DSCP_SYSCTL(28);
DSCP_SYSCTL(29);
DSCP_SYSCTL(30);
DSCP_SYSCTL(31);
DSCP_SYSCTL(32);
DSCP_SYSCTL(33);
DSCP_SYSCTL(34);
DSCP_SYSCTL(35);
DSCP_SYSCTL(36);
DSCP_SYSCTL(37);
DSCP_SYSCTL(38);
DSCP_SYSCTL(39);
DSCP_SYSCTL(40);
DSCP_SYSCTL(41);
DSCP_SYSCTL(42);
DSCP_SYSCTL(43);
DSCP_SYSCTL(44);
DSCP_SYSCTL(45);
DSCP_SYSCTL(46);
DSCP_SYSCTL(47);
DSCP_SYSCTL(48);
DSCP_SYSCTL(49);
DSCP_SYSCTL(50);
DSCP_SYSCTL(51);
DSCP_SYSCTL(52);
DSCP_SYSCTL(53);
DSCP_SYSCTL(54);
DSCP_SYSCTL(55);
DSCP_SYSCTL(56);
DSCP_SYSCTL(57);
DSCP_SYSCTL(58);
DSCP_SYSCTL(59);
DSCP_SYSCTL(60);
DSCP_SYSCTL(61);
DSCP_SYSCTL(62);
DSCP_SYSCTL(63);

static int
rewrite_sysctl_handler_ipv6(SYSCTL_HANDLER_ARGS)
{
        char buf[INET6_ADDRSTRLEN];
        int error;

        inet_ntop(AF_INET6, &rewrite_addresses6[arg2], buf, INET6_ADDRSTRLEN);
        error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
        if (error)
                return (error);
        error = inet_pton(AF_INET6, buf, &rewrite_addresses6[arg2]);
        if (error == 1)
                error = 0;
        return (error);
}

SYSCTL_NODE(_net_inet_ip_dscp_rewrite, OID_AUTO, ip6, CTLFLAG_RD, NULL,
            "DSCP rewrite source IPv6 addresses");

#define DSCP_SYSCTL6(index)                                        \
        SYSCTL_PROC(_net_inet_ip_dscp_rewrite_ip6, (index), index, \
                    CTLTYPE_STRING | CTLFLAG_RW, NULL, (index),    \
                    rewrite_sysctl_handler_ipv6, "A", "DSCP " #index " source IPv6")

DSCP_SYSCTL6(1);
DSCP_SYSCTL6(2);
DSCP_SYSCTL6(3);
DSCP_SYSCTL6(4);
DSCP_SYSCTL6(5);
DSCP_SYSCTL6(6);
DSCP_SYSCTL6(7);
DSCP_SYSCTL6(8);
DSCP_SYSCTL6(9);
DSCP_SYSCTL6(10);
DSCP_SYSCTL6(11);
DSCP_SYSCTL6(12);
DSCP_SYSCTL6(13);
DSCP_SYSCTL6(14);
DSCP_SYSCTL6(15);
DSCP_SYSCTL6(16);
DSCP_SYSCTL6(17);
DSCP_SYSCTL6(18);
DSCP_SYSCTL6(19);
DSCP_SYSCTL6(20);
DSCP_SYSCTL6(21);
DSCP_SYSCTL6(22);
DSCP_SYSCTL6(23);
DSCP_SYSCTL6(24);
DSCP_SYSCTL6(25);
DSCP_SYSCTL6(26);
DSCP_SYSCTL6(27);
DSCP_SYSCTL6(28);
DSCP_SYSCTL6(29);
DSCP_SYSCTL6(30);
DSCP_SYSCTL6(31);
DSCP_SYSCTL6(32);
DSCP_SYSCTL6(33);
DSCP_SYSCTL6(34);
DSCP_SYSCTL6(35);
DSCP_SYSCTL6(36);
DSCP_SYSCTL6(37);
DSCP_SYSCTL6(38);
DSCP_SYSCTL6(39);
DSCP_SYSCTL6(40);
DSCP_SYSCTL6(41);
DSCP_SYSCTL6(42);
DSCP_SYSCTL6(43);
DSCP_SYSCTL6(44);
DSCP_SYSCTL6(45);
DSCP_SYSCTL6(46);
DSCP_SYSCTL6(47);
DSCP_SYSCTL6(48);
DSCP_SYSCTL6(49);
DSCP_SYSCTL6(50);
DSCP_SYSCTL6(51);
DSCP_SYSCTL6(52);
DSCP_SYSCTL6(53);
DSCP_SYSCTL6(54);
DSCP_SYSCTL6(55);
DSCP_SYSCTL6(56);
DSCP_SYSCTL6(57);
DSCP_SYSCTL6(58);
DSCP_SYSCTL6(59);
DSCP_SYSCTL6(60);
DSCP_SYSCTL6(61);
DSCP_SYSCTL6(62);
DSCP_SYSCTL6(63);

// RFC1624のチェックサム計算
static uint16_t checksum_rfc1624(uint16_t orig_checksum, uint16_t old, uint16_t new)
{
        // 元のチェックサムの1の補数を求める
        uint32_t sum;

        // 新しいチェックサムを求める
        // HC' = ~(~HC + ~m + m')
        sum = (~orig_checksum & 0xFFFF) + (~old & 0xFFFF) + new;

        // キャリーオーバー処理
        sum = (sum >> 16) + (sum & 0xffff);
        sum = sum + (sum >> 16);

        // 1の補数を求める
        return ~sum & 0xFFFF;
}

// IPv6アドレスのチェックサム差分の計算
static uint16_t recalculate_checksum_v6(uint16_t orig_checksum, struct in6_addr *orig_ip, struct in6_addr *new_ip)
{
        uint16_t sum = orig_checksum;
        uint16_t *orig_ip_h = (uint16_t *)&orig_ip->s6_addr;
        uint16_t *new_ip_h = (uint16_t *)&new_ip->s6_addr;

        for (int i = 0; i < 8; i++)
        {
                sum = checksum_rfc1624(sum, ntohs(orig_ip_h[i]), ntohs(new_ip_h[i]));
        }

        return sum;
}

// IPv4アドレスのチェックサム差分の計算
static uint16_t recalculate_checksum(uint16_t orig_checksum, uint32_t orig_ip, uint32_t new_ip)
{
        uint16_t sum;
        uint32_t orig_ip_h = orig_ip;
        uint32_t new_ip_h = new_ip;

        uint16_t orig_ip_low = orig_ip_h & 0xFFFF;
        uint16_t orig_ip_high = orig_ip_h >> 16;
        uint16_t new_ip_low = new_ip_h & 0xFFFF;
        uint16_t new_ip_high = new_ip_h >> 16;

        // high bitを処理
        sum = checksum_rfc1624(orig_checksum, orig_ip_high, new_ip_high);
        // low bitを処理
        sum = checksum_rfc1624(sum, orig_ip_low, new_ip_low);

        return sum;
}

#ifdef PFIL_VERSION
static pfil_return_t
dscp_rewrite_in(struct mbuf **m, struct ifnet *ifp, int flags,
                void *ruleset __unused, struct inpcb *inp)
#else
static int
dscp_rewrite_in(void *arg, struct mbuf **m, struct ifnet *ifp,
                int dir, struct inpcb *inp)
#endif
{
        struct ip *ip;
        int dscp = 0;

        if (!dscp_rewrite_enabled)
                return (0);

        ip = mtod(*m, struct ip *);
        if (ip->ip_v != 4)
                return (0);

        /* Extract DSCP field to get index into table;
         * DSCP is the first 6 bits of the 8 bit TOS field. */
        dscp = ip->ip_tos >> 2;

        /* DSCP 0 is always passed through untouched. */
        if (dscp == 0)
                return (0);

        /* If the destination IP for this index is 0, then bail. */
        if (rewrite_addresses[dscp].s_addr == 0)
                return (0);

        size_t ip_hlen = sizeof(struct ip);

        // TCPの場合
        if (ip->ip_p == IPPROTO_TCP)
        {
                struct tcphdr *tcp;
                tcp = (struct tcphdr *)((caddr_t)ip + ip_hlen);
                if (dscp_rewrite_debug)
                        printf("old tcp checksum 0x%04x\n", tcp->th_sum);
                tcp->th_sum = htons(recalculate_checksum(ntohs(tcp->th_sum), ntohl(ip->ip_dst.s_addr), ntohl(rewrite_addresses[dscp].s_addr)));
                if (dscp_rewrite_debug)
                        printf("new tcp checksum 0x%04x\n", tcp->th_sum);
        }

        // UDPの場合
        if (ip->ip_p == IPPROTO_UDP)
        {
                struct udphdr *udp;
                udp = (struct udphdr *)((caddr_t)ip + ip_hlen);
                if (dscp_rewrite_debug)
                        printf("old udp checksum 0x%04x\n", udp->uh_sum);
                udp->uh_sum = htons(recalculate_checksum(ntohs(udp->uh_sum), ntohl(ip->ip_dst.s_addr), ntohl(rewrite_addresses[dscp].s_addr)));
                if (dscp_rewrite_debug)
                        printf("new udp checksum 0x%04x\n", udp->uh_sum);
        }

        if (dscp_rewrite_debug)
                printf("DSCP %d proto %d rewrite to %d.%d.%d.%d => %d.%d.%d.%d\n", dscp, ip->ip_p,
                       ip->ip_dst.s_addr & 0xff, (ip->ip_dst.s_addr >> 8) & 0xff, (ip->ip_dst.s_addr >> 16) & 0xff, (ip->ip_dst.s_addr >> 24) & 0xff,
                       rewrite_addresses[dscp].s_addr & 0xff, (rewrite_addresses[dscp].s_addr >> 8) & 0xff, (rewrite_addresses[dscp].s_addr >> 16) & 0xff, (rewrite_addresses[dscp].s_addr >> 24) & 0xff);

        ip->ip_dst = rewrite_addresses[dscp];

        return (0);
}

#ifdef PFIL_VERSION
static pfil_return_t
dscp_rewrite_in6(struct mbuf **m, struct ifnet *ifp, int flags,
                 void *ruleset __unused, struct inpcb *inp)
#else
static int
dscp_rewrite_in6(void *arg, struct mbuf **m, struct ifnet *ifp,
                 int dir, struct inpcb *inp)
#endif
{
        struct ip6_hdr *ip6;
        int dscp = 0;
        uint8_t tc = 0;

        if (!dscp_rewrite_enabled)
                return (0);

        ip6 = mtod(*m, struct ip6_hdr *);
        if ((ip6->ip6_vfc >> 4) == IPV6_VERSION)
                return (0);

        // Traffic Classを取り出す
        // vfcの後方4ビット、flowの後方4ビットで構成される
        tc = (ip6->ip6_vfc & 0x0F) << 4;
        tc |= ((uint8_t)(ip6->ip6_flow & 0x0000000F));
        // DSCPはTraffic Classの後方6ビット
        dscp = tc >> 2;

        // DSCPが0の場合は処理しない
        if (dscp == 0)
                return (0);

        // DSCPが51以外は処理しない
        if (dscp != 51)
                return (0);

        // rewite_addresses6がip6addr_anyの場合は処理しない
        if (memcmp(&rewrite_addresses6[dscp], &in6addr_any, sizeof(struct in6_addr)) == 0)
                return (0);

        size_t ip6_hlen = sizeof(struct ip6_hdr);
        struct in6_addr orig, new;
        orig = ip6->ip6_dst;
        new = rewrite_addresses6[dscp];

        // TCPの場合
        if (ip6->ip6_nxt == IPPROTO_TCP)
        {
                struct tcphdr *tcp;
                tcp = (struct tcphdr *)((caddr_t)ip6 + ip6_hlen);
                if (dscp_rewrite_debug)
                        printf("old tcp checksum 0x%04x\n", tcp->th_sum);
                tcp->th_sum = htons(recalculate_checksum_v6(ntohs(tcp->th_sum), &orig, &new));
                if (dscp_rewrite_debug)
                        printf("new tcp checksum 0x%04x\n", tcp->th_sum);
        }
        // UDPの場合
        if (ip6->ip6_nxt == IPPROTO_UDP)
        {
                struct udphdr *udp;
                udp = (struct udphdr *)((caddr_t)ip6 + ip6_hlen);
                if (dscp_rewrite_debug)
                        printf("old udp checksum 0x%04x\n", udp->uh_sum);
                udp->uh_sum = htons(recalculate_checksum_v6(ntohs(udp->uh_sum), &orig, &new));
                if (dscp_rewrite_debug)
                        printf("new udp checksum 0x%04x\n", udp->uh_sum);
        }
        // ICMPの場合
        if (ip6->ip6_nxt == IPPROTO_ICMPV6)
        {
                struct icmp6_hdr *icmp;
                icmp = (struct icmp6_hdr *)((caddr_t)ip6 + ip6_hlen);
                if (dscp_rewrite_debug)
                        printf("old icmp checksum 0x%04x\n", icmp->icmp6_cksum);
                icmp->icmp6_cksum = htons(recalculate_checksum_v6(ntohs(icmp->icmp6_cksum), &orig, &new));
                if (dscp_rewrite_debug)
                        printf("new icmp checksum 0x%04x\n", icmp->icmp6_cksum);
        }
        ip6->ip6_dst = rewrite_addresses6[dscp];

        if (dscp_rewrite_debug)
        {
                char orig_str[INET6_ADDRSTRLEN];
                char new_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &orig, orig_str, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &new, new_str, INET6_ADDRSTRLEN);
                printf("DSCP %d proto %d rewrite to %s => %s\n", dscp, ip6->ip6_nxt, orig_str, new_str);
        }

        return (0);
}

static int
dscp_rewrite_modevent(module_t mod, int type, void *arg)
{
        int i;
#ifdef PFIL_VERSION
        struct pfil_hook_args pha, pha6;
        struct pfil_link_args pla, pla6;
#else
        struct pfil_head *pfh_inet, *pfh_inet6;
#endif

        switch (type)
        {
        case MOD_LOAD:
#ifdef PFIL_VERSION
                // IPv4
                pha.pa_version = PFIL_VERSION;
                pha.pa_flags = PFIL_IN;
                pha.pa_modname = "dscp_rewrite";
                pha.pa_ruleset = NULL;
                pha.pa_rulname = "inet";
                pha.pa_func = dscp_rewrite_in;
                pha.pa_type = PFIL_TYPE_IP4;
                pla.pa_version = PFIL_VERSION;
                pla.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
                pfh_hook_inet = pfil_add_hook(&pha);
                pla.pa_hook = pfh_hook_inet;
                pla.pa_head = V_inet_pfil_head;
                pfil_link(&pla);
                // IPv6
                pha6.pa_version = PFIL_VERSION;
                pha6.pa_flags = PFIL_IN;
                pha6.pa_modname = "dscp_rewrite";
                pha6.pa_ruleset = NULL;
                pha6.pa_rulname = "inet6";
                pha6.pa_func = dscp_rewrite_in6;
                pha6.pa_type = PFIL_TYPE_IP6;
                pla6.pa_version = PFIL_VERSION;
                pla6.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
                pfh_hook_inet6 = pfil_add_hook(&pha6);
                pla6.pa_hook = pfh_hook_inet6;
                pla6.pa_head = V_inet6_pfil_head;
                pfil_link(&pla6);
#else
                // IPv4
                pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
                if (pfh_inet == NULL)
                        return (ENOENT);
                // IPv6
                pfh_inet6 = pfil_head_get(PFIL_TYPE_AF, AF_INET6);
                if (pfh_inet6 == NULL)
                        return (ENOENT);
                // hookの追加
                pfil_add_hook(dscp_rewrite_in, NULL, PFIL_IN | PFIL_WAITOK,
                              pfh_inet);
                pfil_add_hook(dscp_rewrite_in6, NULL, PFIL_IN | PFIL_WAITOK,
                              pfh_inet6);
#endif
                break;
        case MOD_UNLOAD:
#ifdef PFIL_VERSION
                // IPv4 hookの削除チェック
                for (i = 0; i < 64; i++)
                {
                        if (rewrite_addresses[i].s_addr != 0)
                                return (EBUSY);
                }
                // IPv6 hookの削除チェック
                for (i = 0; i < 64; i++)
                {
                        if (memcmp(&rewrite_addresses6[i], &in6addr_any, sizeof(struct in6_addr)) != 0)
                                return (EBUSY);
                }
                pfil_remove_hook(pfh_hook_inet);
                pfil_remove_hook(pfh_hook_inet6);
#else
                // IPv4 hookの削除チェック
                pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
                if (pfh_inet == NULL)
                        return (ENOENT);
                for (i = 0; i < 64; i++)
                {
                        if (rewrite_addresses[i].s_addr != 0)
                                return (EBUSY);
                }
                // IPv6 hookの削除チェック
                pfh_inet6 = pfil_head_get(PFIL_TYPE_AF, AF_INET6);
                if (pfh_inet6 == NULL)
                        return (ENOENT);
                for (i = 0; i < 64; i++)
                {
                        if (memcmp(&rewrite_addresses6[i], &in6addr_any, sizeof(struct in6_addr)) != 0)
                                return (EBUSY);
                }
                // hookの削除
                pfil_remove_hook(dscp_rewrite_in, NULL, PFIL_IN | PFIL_WAITOK,
                                 pfh_inet);
                pfil_remove_hook(dscp_rewrite_in6, NULL, PFIL_IN | PFIL_WAITOK,
                                 pfh_inet6);
#endif
                break;
        case MOD_QUIESCE:
                break;
        default:
                return (EOPNOTSUPP);
        }
        return (0);
}

static moduledata_t dscp_rewrite_mod = {
    "dscp_rewrite",
    dscp_rewrite_modevent,
    0,
};

DECLARE_MODULE(dscp_rewrite, dscp_rewrite_mod, SI_SUB_PROTO_IFATTACHDOMAIN,
               SI_ORDER_ANY);
MODULE_VERSION(dscp_rewrite, 1);