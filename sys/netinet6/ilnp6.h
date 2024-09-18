/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2019-2020  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 2020-2024 Gregor Haywood
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETINET6_ILNP6_H
#define _NETINET6_ILNP6_H

#include <sys/types.h>
#include <sys/mutex.h>
#ifdef _KERNEL
#include <sys/fnv_hash.h>
#include <sys/libkern.h>
#include <net/vnet.h>
#include <vm/uma.h>
#endif
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>

/* NID/L64/nonce (max 12 bytes) string lengths. */
#define ILNP6_NIDSTRLEN	20
#define ILNP6_L64STRLEN	20
#define ILNP6_ILVSTRLEN	40
#define ILNP6_NONCESTRLEN	25

/*
 * Common ILNP6 NID and L64 structure.
 * The 32 bit field is mainly for alignment.
 */
struct ilnp6_addr {
	union {
		uint8_t		__ui6_addr8[8];
		uint32_t	__ui6_addr32[2];
	} __ui6_addr;
#define i6_addr		__ui6_addr.__ui6_addr8
};
#define ilnp6_nid	ilnp6_addr
#define ilnp6_l64	ilnp6_addr

#define ILNP6_ARE_ADDR_EQUAL(a, b)	\
    (bcmp(&(a)->i6_addr[0], &(b)->i6_addr[0], sizeof(struct ilnp6_addr)) == 0)

#define ILNP6_ARE_NID_EQUAL(a, b)	ILNP6_ARE_ADDR_EQUAL(a, b)
#define ILNP6_ARE_L64_EQUAL(a, b)	ILNP6_ARE_ADDR_EQUAL(a, b)

#define ILNP6_IS_ADDR_ZERO(a)	\
    ((a)->__ui6_addr.__ui6_addr32[0] == 0 && \
     (a)->__ui6_addr.__ui6_addr32[1] == 0)

#define ILNP6_IS_NID_ZERO(a)		ILNP6_IS_ADDR_ZERO(a)
#define ILNP6_IS_L64_ZERO(a)		ILNP6_IS_ADDR_ZERO(a)

#define ILNP6_IS_L64_GLOBAL_UNICAST(a)	(((a)->i6_addr[0] & 0xe0) == 0x20)

#define ILNP6_ADDR_COPY(a, b)		\
    bcopy(&(a)->i6_addr[0], &(b)->i6_addr[0], sizeof(struct ilnp6_addr))

#define ILNP6_NID_COPY(a, b)		ILNP6_ADDR_COPY(a, b)
#define ILNP6_L64_COPY(a, b)		ILNP6_ADDR_COPY(a, b)

/*
 * ILNP6 I_L vector structure.
 */
struct ilnp6_ilv {
	union {
		struct in6_addr		__ui6_ipv6;
		struct ilnp6_addr	__ui6_ilnp[2];
	} __ui6_ilv;
#define ilv_ipv6	__ui6_ilv.__ui6_ipv6
#define ilv_l64		__ui6_ilv.__ui6_ilnp[0]
#define ilv_nid		__ui6_ilv.__ui6_ilnp[1]
};

#define ILNP6_IPV6_TO_ILV(a)	((const struct ilnp6_ilv *)a)
#define ILNP6_IPV6_TO_L64(a)	&ILNP6_IPV6_TO_ILV(a)->ilv_l64
#define ILNP6_IPV6_TO_NID(a)	&ILNP6_IPV6_TO_ILV(a)->ilv_nid

#define ILNP6_IPV6_TO_MUT_ILV(a)	((struct ilnp6_ilv *)a)
#define ILNP6_IPV6_TO_MUT_L64(a)	&ILNP6_IPV6_TO_MUT_ILV(a)->ilv_l64
#define ILNP6_IPV6_TO_MUT_NID(a)	&ILNP6_IPV6_TO_MUT_ILV(a)->ilv_nid

#define ILNP6_ARE_ILV_EQUAL(a, b) IN6_ARE_ADDR_EQUAL(&(a)->ilv_ipv6, &(b)->ilv_ipv6)
#define ILNP6_NID_MATCH(a, b)		\
	(ILNP6_IS_ILV_GLOBAL_UNICAST(ILNP6_IPV6_TO_ILV(a)) && \
	 ILNP6_IS_ILV_GLOBAL_UNICAST(ILNP6_IPV6_TO_ILV(b)) && \
	 ILNP6_ARE_NID_EQUAL(ILNP6_IPV6_TO_NID(a), ILNP6_IPV6_TO_NID(b)))

#define ILNP6_IS_ILV_GLOBAL_UNICAST(a)	(((a)->ilv_ipv6.s6_addr[0] & 0xe0) == 0x20)
#define ILNP6_IS_ILV_ZERO(a)	IN6_IS_ADDR_UNSPECIFIED(&(a)->ilv_ipv6)
#define ILNP6_ILV_COPY(a, b)	bcopy(&(a)->ilv_ipv6.s6_addr[0], &(b)->ilv_ipv6.s6_addr[0], sizeof(struct ilnp6_ilv))

/*
 * ILNP nonce option.
 * ion_nonce has room for a long (12 byte vs short 4 byte) nonce.
 */
struct ilnp_nonce_opt {
	struct ip6_opt	ion_opt;		/* option header. */
	uint8_t		ion_nonce[12];		/* nonce. */
};

/*
 * ILNP nonce destination option.
 */
struct ilnp_nonce_dest {
	struct ip6_dest	idn_dest;		/* destination header. */
	struct ilnp_nonce_opt idn_nonce_opt;	/* nonce option. */
};
#define idn_opt		idn_nonce_opt.ion_opt
#define idn_nonce	idn_nonce_opt.ion_nonce

#define ILNP6_NONCE_LEN(n)	((n)->ion_opt.ip6o_len)
#define ILNP6_NONCE_OPTLEN(n)	(ILNP6_NONCE_LEN(n) + sizeof(struct ip6_opt))
#define	ILNP6_NONCE_DESTLEN(n)	(ILNP6_NONCE_OPTLEN(n) + sizeof(struct ip6_dest))

/* Compare two struct ilnp_nonce_opt*. */
#define ILNP6_ARE_NONCE_EQUAL(a, b)		\
    (ILNP6_NONCE_LEN(a) == ILNP6_NONCE_LEN(b)) && \
    (bcmp(&(a)->ion_nonce, &(b)->ion_nonce, ILNP6_NONCE_LEN(a)) == 0)

/* Copy a nonce. */
#define ILNP6_NONCE_COPY(a, b)	bcopy(a, b, ILNP6_NONCE_OPTLEN(a));

/*
 * Local node IOCTL request.
 */
struct ilnp6_lreq {
	struct ilnp6_ilv	lr_ilv;		/* Contains NID/l64. */
#define lr_nid			lr_ilv.ilv_nid	/* Local NID. */
#define lr_l64			lr_ilv.ilv_l64	/* Local L64. */
	struct in6_addr		lr_gw;		/* Gateway for next hop. */
	uint32_t		lr_pref;	/* preference. */
	u_short			lr_if;		/* Index of iface for L64. */
	uint32_t		lr_flags;	/* Validity flags. */
	time_t			lr_expire;	/* Time at which entry expires. */
	unsigned int		lr_refs;	/* Reference count. */
};

#define ILNP6_INVALID_PREF	UINT32_MAX
#define ILNP6_MAXVALID_PREF	UINT16_MAX

#define SIOCSLOCAL_ILNP6	 _IOW('I', 60, struct ilnp6_lreq)
#define SIOCGLOCAL_ILNP6	_IOWR('I', 60, struct ilnp6_lreq)
#define SIOCFLOCAL_ILNP6	 _IOW('I', 61, struct ilnp6_lreq)

/*
 * Remote node IOCTL request.
 */
struct ilnp6_nreq {
	struct ilnp6_ilv	nr_ilv;		/* ILV (contains NID & L64). */
#define nr_nid			nr_ilv.ilv_nid	/* The NID. */
#define nr_l64			nr_ilv.ilv_l64	/* The L64. */
	time_t			nr_nidexpire;	/* NID expire date. */
	size_t			nr_l64count;	/* Total number of l64s. */
	size_t			nr_l64index;	/* The l64 to return. */
	uint32_t		nr_l64pref;	/* L64 pref. */
	time_t			nr_l64expire;	/* L64 expire date. */
	struct ilnp6_nid	nr_snid;	/* Source NID value. */
	uint8_t			nr_flags;	/* Flags. */
	unsigned int		nr_refcount;	/* Reference count. */

	struct ilnp_nonce_opt	nr_rnonce;		/* Remote nonce. */
	struct ilnp_nonce_opt	nr_lnonce;		/* Local nonce. */

	time_t			nr_nidlastsent;	/* Stats only. */
	time_t			nr_nidlastrcvd;	/* Stats only. */
	time_t			nr_l64lastsent;	/* Stats only. */
	time_t			nr_l64lastrcvd;	/* Stats only. */
};


#define SIOCSNODE_ILNP6		 _IOW('I', 65, struct ilnp6_nreq)
#define SIOCGNODE_ILNP6		_IOWR('I', 65, struct ilnp6_nreq)
#define SIOCFNODE_ILNP6		 _IOW('I', 66, struct ilnp6_nreq)

/*
 * Node flags.
 */

/* Remote nodes */
#define ILNP6_FOREIGN_ERROR	1	/* Remote node does not support ILNP. */
#define ILNP6_FOREIGN_LUPENDING	2	/* locator update ack pending */
#define ILNP6_FOREIGN_NONCE_SET	4	/* The remote nonce has not yet been set */
#define ILNP6_FOREIGN_ADDRINFO	8	/* The entry is addrinfo, and not a connection. */

/* Local node flags. */
#define ILNP6_LOCAL_AGED	1	/* A NID that should not be used in new connections. */
#define ILNP6_LOCAL_EXPIRED	2	/* An l64 that should be purged soon. */
#define ILNP6_LOCAL_EPHEMERAL	4	/* Use in only one connection. */
#define ILNP6_LOCAL_OPTIMISTIC	8	/* DAD incomplete. */
#define ILNP6_LOCAL_MANAGED	16	/* We added this NID to an interface, so must remove it. */
#define ILNP6_LOCAL_USED	32	/* An ephemeral NID that has been used at least once. */
#define ILNP6_LOCAL_ACTIVE	64	/* An ephemeral NID that is in use. */

/*
 * Sysctl defines.
 */
#ifdef _KERNEL

/* Default values. */
#define ILNP6_ENABLE		0
#define ILNP6_EPHEMERAL_POOL	0
#define ILNP6_LOCALL64PREF	10
#define ILNP6_LOCALNIDPREF	10
#define ILNP6_LOCALL64TTL	30
#define ILNP6_LUMAXDELAY	1
#define ILNP6_LUMAXRETRANS	7
#define ILNP6_LUTTL		300
#define ILNP6_NIDHASHSIZE	8
#define ILNP6_NONCESIZE		4
#define ILNP6_ONINPUTPREF	0
#define ILNP6_ONINPUTTTL	10
#define ILNP6_PRUNE		10

VNET_DECLARE(int, ilnp6_enable);
VNET_DECLARE(int, ilnp6_ephemeral_pool);
VNET_DECLARE(int, ilnp6_local_l64_pref);
VNET_DECLARE(int, ilnp6_local_nid_pref);
VNET_DECLARE(int, ilnp6_local_l64_ttl);
VNET_DECLARE(int, ilnp6_lu_max_delay);
VNET_DECLARE(int, ilnp6_lu_max_retrans);
VNET_DECLARE(int, ilnp6_lu_ttl);
VNET_DECLARE(int, ilnp6_nid_hash_size);
VNET_DECLARE(int, ilnp6_nonce_size);
VNET_DECLARE(int, ilnp6_on_input_pref);
VNET_DECLARE(int, ilnp6_on_input_ttl);
VNET_DECLARE(int, ilnp6_prune);

#define V_ilnp6_enable		VNET(ilnp6_enable)
#define V_ilnp6_ephemeral_pool	VNET(ilnp6_ephemeral_pool)
#define V_ilnp6_local_l64_pref	VNET(ilnp6_local_l64_pref)
#define V_ilnp6_local_nid_pref	VNET(ilnp6_local_nid_pref)
#define V_ilnp6_local_l64_ttl	VNET(ilnp6_local_l64_ttl)
#define V_ilnp6_lu_max_delay	VNET(ilnp6_lu_max_delay)
#define V_ilnp6_lu_max_retrans	VNET(ilnp6_lu_max_retrans)
#define V_ilnp6_lu_ttl		VNET(ilnp6_lu_ttl)
#define V_ilnp6_nid_hash_size	VNET(ilnp6_nid_hash_size)
#define V_ilnp6_nonce_size	VNET(ilnp6_nonce_size)
#define V_ilnp6_on_input_ttl    VNET(ilnp6_on_input_ttl)
#define V_ilnp6_on_input_pref	VNET(ilnp6_on_input_pref)
#define V_ilnp6_prune		VNET(ilnp6_prune)
/*
 * ILCC local node structures.
 */
LIST_HEAD(localnidhead, localnid);
LIST_HEAD(locall64head, locall64);


/*
 * Local NID.
 * Two local NIDs cannot be compared in a meaningfully, so
 * the order of this list is unimportant.
 */
struct localnid {
	LIST_ENTRY(localnid)	ln_list;	/* Local NID list. */
	struct ilnp6_nid	ln_nid;		/* Local NID. */
	uint32_t		ln_pref;	/* Preference. */
	uint32_t		ln_flags;	/* Flags. */
	unsigned int		ln_refs;	/* Reference count. */
};

/* Local locator. */
struct locall64 {
	LIST_ENTRY(locall64)	ll_list;	/* local locator list. */
	struct ilnp6_l64	ll_l64;		/* local locator. */
	struct in6_addr		ll_gw;		/* Gateway for outbound packets. */
	uint32_t		ll_pref;	/* preference. */
	time_t			ll_expire;	/* Uptime-based expiery from last RA, or 0 if static. */
	time_t			ll_recv;	/* Uptime-based expiery from last recieved packet. */
	uint32_t		ll_flags;	/* Flags. */
	u_short			ll_if;		/* Interface index for this L64. */
	int32_t			ll_score;	/* Metric indicating use frequency. */
};

/*
 * ILCC remote node structures.
 */
LIST_HEAD(foreignnidhead, foreignnid);
LIST_HEAD(foreignl64head, foreignl64);

/* Remote node. */
struct foreignnid {
	LIST_ENTRY(foreignnid)	n_list;		/* All nodes/all addrinfo linked list. */
	LIST_ENTRY(foreignnid)	n_nidhash;	/* NID hash collision linked list. */
	struct ilcc		*n_ilcc;	/* back pointer to ilcc. */

	struct ilnp6_nid	n_nid;		/* Remote NID. */
	struct foreignl64head	n_l64list;	/* L64 list (smallest pref first). */
	int l64_idx;

	uint8_t			n_flags;	/* Flags */
	time_t			n_expire;	/* Explicit time to expire (DNS/LU). */
	unsigned int		n_refcount;	/* Connected INPs. */

	struct ilnp6_nid	n_lnid;		/* Local NID (needed for LUs). */

	/* NOTE: a bidrectional nonce is used. */
	struct ilnp_nonce_opt	n_nonce;	/* Bidirectional nonce. */
#define n_lnonce			n_nonce
#define n_rnonce			n_nonce
	// struct ilnp_nonce_opt	n_lnonce;	/* Local/outbound nonce. */
	// struct ilnp_nonce_opt	n_rnonce;	/* Remote/inbound nonce. */

	int			n_luretrans;	/* locator update retrans. */
	struct callout		n_lucallout;	/* locator update callout. */
};

/* Remote node locator. */
struct foreignl64 {
	LIST_ENTRY(foreignl64)	l_list;		/* Per-NID L64 list (smallest pref first). */
	struct ilnp6_l64	l_l64;		/* L64. */
	uint32_t		l_pref;		/* Preference. */
	time_t			l_expire;	/* Explicitly set time to expire (DNS/LU). Unused. */
};

/*
 * ILCC (ILNP Communication Cache) structure.
 */
struct ilcc {
	/* locks & managment. */
	struct mtx		cc_lock;	/* Global lock. */
	struct uma_zone		*cc_zone;	/* UMA zone. */
	struct vnet		*cc_vnet;	/* Network stack instance. */

	/* local part */
	struct localnidhead	cc_lnidlist;	/* Local NID list (smallest pref first). */
	struct locall64head	cc_ll64list;	/* Local L64 list (smallest pref first). */
	unsigned long		cc_localgencnt;	/* Local L64 generation count. */
	unsigned int		cc_nidpool;

	/* remote node part. */
	struct foreignnidhead	cc_addrinfolist;/* List of addrinfo entries mngmt. */
	struct foreignnidhead	cc_tnidlist;	/* List of tentative remote NIDs. */
	struct foreignnidhead	cc_fnidlist;	/* List of remote NIDs for mngmt. */
	struct foreignnidhead	*cc_nhashbase;	/* Hash table of remote NIDs. */
	unsigned long		cc_nhashmask;	/* Remote nid hash mask. */

	/* periodic cache cleanup. */
	struct callout		cc_callout;	/* prune callout. */

	/* locator update. */
	uint8_t			cc_lul64count;	/* LU locator count. */
	struct ilnp_lu_l64	*cc_lul64s;	/* LU locator entries. */
};

#define ILCC_LOCK_INIT(ilp)	mtx_init(&(ilp)->cc_lock, "ilcc", NULL, MTX_DEF | MTX_RECURSE)
#define ILCC_LOCK_DESTROY(ilp)	mtx_destroy(&(ilp)->cc_lock)
#define ILCC_LOCK(ilp)		mtx_lock(&(ilp)->cc_lock)
#define ILCC_UNLOCK(ilp)	mtx_unlock(&(ilp)->cc_lock)
#define ILCC_LOCK_ASSERT(ilp)	mtx_assert(&(ilp)->cc_lock, MA_OWNED)
#define ILCC_UNLOCK_ASSERT(ilp) mtx_assert(&(ilp)->cc_lock, MA_NOTOWNED)

#define ILNP6NID_HASHVAL(n)	(ilnp6_nidhash(n))
#define ILNP6NID_HASH_BUCKET(ilp, n)	&(ilp)->cc_nhashbase[ilnp6_nidhash(n) & (ilp)->cc_nhashmask]

static __inline uint32_t
ilnp6_nidhash(const struct ilnp6_nid *n)
{
	return (fnv_32_buf(n, 8, FNV1_32_INIT));
}

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_ILNP6);
#endif

VNET_DECLARE(struct ilcc, ilcc);
#define	V_ilcc		VNET(ilcc)

int	ilnp6_dstopts_nonce_offset(struct ip6_dest *, int);
int	ilnp6_ioctl(unsigned long, caddr_t);
int	ilnp6_lu_input(struct mbuf *, int, int);
int	ilnp6_nonce_input(struct ip6_dest *, uint8_t *, struct mbuf *);
int	ilnp6_nonce_optlen(struct ilcc *, struct inpcb *);
int	ilnp6_nonce_output(struct ilcc *, struct ilnp_nonce_dest *, struct inpcb *);
int	ilnp6_nonce_output_mbuf(struct ilcc *, struct ilnp_nonce_dest *, struct mbuf *);
int	ilnp6_nonce_output_np(struct ilcc *, struct ilnp_nonce_dest *, struct foreignnid *);
char   *ilnp6_nonce_sprintf(char *, const struct ilnp_nonce_opt *);
int	ilnp6_npconnect(struct ilcc *, struct foreignnid **, struct in6_addr *, struct in6_addr *);
int	ilnp6_npdisconnect(struct ilcc *, struct foreignnid **);
int	ilnp6_ra_input(struct in6_addr *, struct in6_addr *, u_char, uint32_t, struct ifnet *);
int	ilnp6_pcbconnect(struct ilcc *, struct inpcb *, struct in6_addr *, struct in6_addr *, int *);
int	ilnp6_pcbdisconnect(struct ilcc *, struct inpcb *);
int	ilnp6_pcbupdate(struct ilcc *, struct inpcb *, struct in6_addr *);
int	ilnp6_selectsrc(struct ilnp6_ilv *, struct ilcc *, struct inpcb *, const struct in6_addr *, struct ifnet *);
char   *ilnp6_sprintf(char *, const struct ilnp6_addr *);
int	ilnp6_unreachable_l64(struct ilcc *, struct inpcb *, struct in6_addr *);
int	ilnp6_update_inpcb(struct ilcc *, struct inpcb *, struct ip6_hdr *);
int	ilnp6_update_np(struct ilcc *, struct in6_addr *, struct in6_addr *, struct foreignnid *);
int	is_dst_ilnp6(struct ilcc *, struct in6_addr *, struct in6_addr *);
int	is_mbuf_ilnp6(struct mbuf *);

int	is_ilnp6_mbuf_fw(struct mbuf **, int);

void   ilnp6_paramprob_input(struct mbuf **, int, int);

int	ilnp6_cksum_pseudo(struct ip6_hdr *, uint32_t, uint8_t, uint16_t);
int	ilnp6_cksum(struct mbuf *, uint8_t, uint32_t, uint32_t);
int	ilnp6_cksum_partial(struct mbuf *, uint8_t, uint32_t, uint32_t, uint32_t);

int ilnp6_if_unroute(struct ilcc *, struct ifnet *);

#endif /* _KERNEL */

#endif /* !_NETINET6_ILNP6_H */
