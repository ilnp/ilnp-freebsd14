/*-
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

#include <sys/cdefs.h>
#include <sys/param.h>

/* This header file must be included here. */
#include "opt_inet6.h"

#include <sys/errno.h>
#include <sys/eventhandler.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/if_llatbl.h>
#include <net/if_var.h>
#include <net/route/nhop.h>

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip6.h>

#include <netinet6/ilnp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>


static int	addrinfo_delete(struct ilcc *, struct foreignnid *);
static struct foreignnid *	addrinfo_lookup(struct ilcc *, const struct ilnp6_nid *, const struct ilnp6_l64 *);
static int	addrinfo_update(struct ilcc *, const struct ilnp6_ilv *, time_t, time_t, uint32_t);
static int	foreignl64_delete(struct foreignl64 *);
static struct foreignl64 *	foreignl64_lookup(struct foreignnid *, const struct ilnp6_l64 *);
static int	foreignl64_update(struct foreignnid *, const struct ilnp6_l64 *, uint32_t, time_t);
static int	foreignnid_destroy(struct ilcc *, struct foreignnid *);
static int	foreignnid_delete(struct ilcc *, struct foreignnid *);
static void	foreignnid_fini(void *, int);
static int	foreignnid_init(void *, int, int);
static struct foreignnid *	foreignnid_lookup(struct ilcc *, const struct ilnp6_nid *, const struct ilnp6_l64 *, const struct ilnp6_nid *);
static struct foreignnid *	foreignnid_lookup_inpcb(struct inpcb *);
static struct foreignnid *	foreignnid_lookup_nonce(struct ilcc *, const struct ilnp6_nid *, const struct ilnp_nonce_opt *);
static int	foreignnid_update(struct ilcc *, struct foreignnid **, const struct ilnp6_nid *, const struct ilnp6_l64 *, const struct ilnp6_nid *);
static void	ilcc_init(struct ilcc *);
static void	ilcc_destroy(struct ilcc *);
static void	ilcc_purge(void *);
static void	ilcc_zone_change(void *);
static int	is_ilnp6_mbuf_fw_hdr(struct mbuf *, int *, int *);
static int	locall64_delete(struct ilcc *, struct locall64 *);
static void	locall64_destroy(struct ilcc *, struct locall64 *);
static struct locall64 *	locall64_lookup(struct ilcc *, const struct ilnp6_l64 *);
static struct locall64 *	locall64_select(struct ilcc *, struct ifnet *);
static struct locall64 *	locall64_select_best(struct ilcc *, int32_t);
static int	locall64_update(struct ilcc *, const struct ilnp6_l64 *, const struct in6_addr *, uint32_t, time_t, u_short);
static int	localnid_age(struct ilcc *, struct localnid *);
static int	localnid_add_ephemeral(struct ilcc *);
static int	localnid_dereference(struct ilcc *, struct localnid *);
static void	localnid_destroy(struct ilcc *, struct localnid *);
static struct localnid *	localnid_lookup(struct ilcc *, const struct ilnp6_nid *);
static int	localnid_update(struct ilcc *, struct ilnp6_nid *, uint32_t, uint32_t);
static int	localnid_update_locked(struct ilcc *, struct ilnp6_nid *, uint32_t, uint32_t);
static int	lu_input_advert(struct mbuf *, int);
static int	lu_input_ack(struct mbuf *, int);
static int	lu_output_schedule(struct ilcc *);
static void	lu_output(void *);
static int	selectsrc_inp(struct ilnp6_ilv *, struct ilcc *, struct inpcb *, const struct ilnp6_ilv *, struct ifnet *);
static int	selectsrc_addr(struct ilnp6_ilv *, struct ilcc *, const struct ilnp6_ilv *, struct ifnet *);
static int	sysctl_ilnp6_locall64list(SYSCTL_HANDLER_ARGS);
static int	sysctl_ilnp6_localnidlist(SYSCTL_HANDLER_ARGS);
static int	sysctl_ilnp6_nodelist(SYSCTL_HANDLER_ARGS);
static int	sysctl_ilnp6_nonce_size(SYSCTL_HANDLER_ARGS);
static int	sysctl_ilnp6_lu_outputs(SYSCTL_HANDLER_ARGS);
static int	tentativenid_delete(struct ilcc *, struct foreignnid *);
static int	tentativenid_update(struct ilcc *, const struct ilnp6_nid *, const struct ilnp6_l64 *, const struct ilnp6_nid *, struct ilnp_nonce_opt *);
static void	vnet_ilcc_init(const void *);
static void	vnet_ilcc_destroy(const void *);


VNET_DEFINE(struct ilcc, ilcc);

MALLOC_DEFINE(M_ILNP6, "ilnp6", "Identifier Locator Network Protocol v6");

/*
 * Identifier Locator Network Protocol v6.
 */
FEATURE(ilnp6, "Identifier Locator Network Protocol version 6");

/*
 * sysctl related items.
 */
SYSCTL_DECL(_net_inet6);
SYSCTL_NODE(_net_inet6, OID_AUTO, ilnp6, CTLFLAG_RW, 0, "ILNP6");

VNET_DEFINE(int, ilnp6_enable) = ILNP6_ENABLE;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, enable,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_enable), 0,
    "Enable Identifier Locator Network Protocol v6");

/* TODO: if this changes, we need to generate or remove some NIDs */
VNET_DEFINE(int, ilnp6_ephemeral_pool) = ILNP6_EPHEMERAL_POOL;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, ephemeralnidpool,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_ephemeral_pool), 0,
    "Set the ephemeral NID pool size (0 disableds ephemeral NIDs)");

VNET_DEFINE(int, ilnp6_local_l64_pref) = ILNP6_LOCALL64PREF;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, locall64pref,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_local_l64_pref), 0,
    "Default precedence of local L64s learnt from RAs");

VNET_DEFINE(int, ilnp6_local_nid_pref) = ILNP6_LOCALNIDPREF;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, localnidpref,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_local_nid_pref), 0,
    "Default precedence of local ephemeral NIDs");

VNET_DEFINE(int, ilnp6_local_l64_ttl) = ILNP6_LOCALL64TTL;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, locall64ttl,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_local_l64_ttl), 0,
    "Time to consider a locaal L64 live after recieving an RA or packet");

VNET_DEFINE(int, ilnp6_lu_max_delay) = ILNP6_LUMAXDELAY;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, lumaxdelay,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_lu_max_delay), 0,
    "Maximum delay before sending a locator update");

VNET_DEFINE(int, ilnp6_lu_max_retrans) = ILNP6_LUMAXRETRANS;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, lumaxretrans,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_lu_max_retrans), 0,
    "Maximum locator update retransmission");

VNET_DEFINE(int, ilnp6_lu_ttl) = ILNP6_LUTTL;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, luttl,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_lu_ttl), 0,
    "Time to live to use in locator updates");

VNET_DEFINE(int, ilnp6_nid_hash_size) = ILNP6_NIDHASHSIZE;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, nidhashsize,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(ilnp6_nid_hash_size), 0,
    "Size of ILNP6 remote node NID hashtable");

/* Nonce size must be 4 (32 bits) or 12 (96 bits) */
VNET_DEFINE(int, ilnp6_nonce_size) = ILNP6_NONCESIZE;
static int
sysctl_ilnp6_nonce_size(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = V_ilnp6_nonce_size;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || !req->newptr)
		return (error);
	if ((val != 4) && (val != 12))
		return (EINVAL);
	V_ilnp6_nonce_size = val;
	return (0);
}
SYSCTL_PROC(_net_inet6_ilnp6, OID_AUTO, noncesize,
    CTLFLAG_VNET | CTLTYPE_INT | CTLFLAG_RW, NULL, 0,
    sysctl_ilnp6_nonce_size, "I",
    "ILNP6 nonce size (4 or 12 octets)");

VNET_DEFINE(int, ilnp6_on_input_pref) = ILNP6_ONINPUTPREF;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, oninputpref,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_on_input_pref), 0,
    "Default precedence for remote entries from inbound packets");

VNET_DEFINE(int, ilnp6_on_input_ttl) = ILNP6_ONINPUTTTL;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, oninputttl,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_on_input_ttl), 0,
    "Default TTL for remote entries from inbound packets");

VNET_DEFINE(int, ilnp6_prune) = ILNP6_PRUNE;
SYSCTL_INT(_net_inet6_ilnp6, OID_AUTO, ilccprune,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(ilnp6_prune), 0,
    "Time between ILCC purge runs");


/*
 * List of local nids.
 */
static int
sysctl_ilnp6_localnidlist(SYSCTL_HANDLER_ARGS)
{
	struct ilnp6_nid nid;
	struct localnid *lnp;
	int error;

	if (req->newptr)
		return (EPERM);

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	bzero(&nid, sizeof(nid));
	ILCC_LOCK(&V_ilcc);
	LIST_FOREACH(lnp, &V_ilcc.cc_lnidlist, ln_list) {
		ILNP6_NID_COPY(&lnp->ln_nid, &nid);
		error = SYSCTL_OUT(req, &nid, sizeof(nid));
		if (error != 0)
			break;
	}
	ILCC_UNLOCK(&V_ilcc);
	return (error);
}

SYSCTL_PROC(_net_inet6_ilnp6, OID_AUTO, localnidlist,
    CTLFLAG_VNET | CTLTYPE_OPAQUE | CTLFLAG_RD, NULL, 0,
    sysctl_ilnp6_localnidlist, "S,ilnp6_nid",
    "ILNP6 local nid list");

/*
 * List of local locators.
 */
static int
sysctl_ilnp6_locall64list(SYSCTL_HANDLER_ARGS)
{
	struct ilnp6_l64 l64;
	struct locall64 *llp;
	int error;

	if (req->newptr)
		return (EPERM);

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	bzero(&l64, sizeof(l64));
	ILCC_LOCK(&V_ilcc);
	LIST_FOREACH(llp, &V_ilcc.cc_ll64list, ll_list) {
		ILNP6_L64_COPY(&llp->ll_l64, &l64);
		error = SYSCTL_OUT(req, &l64, sizeof(l64));
		if (error != 0)
			break;
	}
	ILCC_UNLOCK(&V_ilcc);
	return (error);
}

SYSCTL_PROC(_net_inet6_ilnp6, OID_AUTO, locall64list,
    CTLFLAG_VNET | CTLTYPE_OPAQUE | CTLFLAG_RD, NULL, 0,
    sysctl_ilnp6_locall64list, "S,ilnp6_loc",
    "ILNP6 local locator list");


#if 0
/*
 * List of foreign locators.
 *
 * TODO Implement
 *
 * Ideally, provide binary data: NID, src NID, and nonce
 */
static int
sysctl_ilnp6_foreignl64list(SYSCTL_HANDLER_ARGS)
{
	struct ilnp6_l64 l64;
	struct locall64 *llp;
	int error;

	if (req->newptr)
		return (EPERM);

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	bzero(&l64, sizeof(l64));
	ILCC_LOCK(&V_ilcc);
	LIST_FOREACH(llp, &V_ilcc.cc_ll64list, ll_list) {
		ILNP6_L64_COPY(&llp->ll_l64, &l64);
		error = SYSCTL_OUT(req, &l64, sizeof(l64));
		if (error != 0)
			break;
	}
	ILCC_UNLOCK(&V_ilcc);
	return (error);
}

SYSCTL_PROC(_net_inet6_ilnp6, OID_AUTO, foreignl64list,
    CTLFLAG_VNET | CTLTYPE_OPAQUE | CTLFLAG_RD, NULL, 0,
    sysctl_ilnp6_foreignl64list, "S,ilnp6_loc",
    "ILNP6 foreign locator list");

SYSCTL_STRUCT(parent, number, name, ctlflags, ptr,	struct_type, descr);

#endif

/*
 * List of remote node i_l vectors.
 */
static int
sysctl_ilnp6_nodelist(SYSCTL_HANDLER_ARGS)
{
	struct ilnp6_ilv ilv, nid;
	struct foreignnid *np;
	int error;

	if (req->newptr)
		return (EPERM);

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	bzero(&ilv, sizeof(ilv));
	bzero(&nid, sizeof(nid));
	ILCC_LOCK(&V_ilcc);
	LIST_FOREACH(np, &V_ilcc.cc_fnidlist, n_list) {
		ILNP6_NID_COPY(&np->n_nid, &ilv.ilv_nid);
		ILNP6_L64_COPY(&LIST_FIRST(&np->n_l64list)->l_l64, 
		    &ilv.ilv_l64);
		error = SYSCTL_OUT(req, &ilv, sizeof(ilv));
		if (error != 0)
			break;
		ILNP6_NID_COPY(&np->n_lnid, &nid.ilv_nid);
		error = SYSCTL_OUT(req, &nid, sizeof(nid));
		if (error != 0)
			break;
	}
	/* Nameinfo assumes unique NID. */
	bzero(&ilv, sizeof(ilv));
	bzero(&nid, sizeof(nid));
	LIST_FOREACH(np, &V_ilcc.cc_addrinfolist, n_list) {
		ILNP6_NID_COPY(&np->n_nid, &ilv.ilv_nid);
		error = SYSCTL_OUT(req, &ilv, sizeof(ilv));
		if (error != 0)
			break;
		error = SYSCTL_OUT(req, &nid, sizeof(nid));
		if (error != 0)
			break;
	}
	ILCC_UNLOCK(&V_ilcc);
	return (error);
}
SYSCTL_PROC(_net_inet6_ilnp6, OID_AUTO, nodelist,
    CTLFLAG_VNET | CTLTYPE_OPAQUE | CTLFLAG_RD, NULL, 0,
    sysctl_ilnp6_nodelist, "S,in6_addr",
    "ILNP6 remote node	I_L vector list");

static int
sysctl_ilnp6_lu_outputs(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr || !V_ilnp6_enable)
		return (error);

	ILCC_LOCK(&V_ilcc);
	error = lu_output_schedule(&V_ilcc);
	ILCC_UNLOCK(&V_ilcc);

	return (0);
}
SYSCTL_PROC(_net_inet6_ilnp6, OID_AUTO, sendlocatorupdates,
    CTLFLAG_VNET | CTLTYPE_INT | CTLFLAG_RW, NULL, 0,
    sysctl_ilnp6_lu_outputs, "I",
    "Send locator updates");

/*
 * Initialize an ILNP remote node (UMA zone managment).
 */
static int
foreignnid_init(void *mem, int size, int flags)
{
	return (0);
}

/*
 * Finalize an ILNP remote node (UMA zone managment).
 */
static void
foreignnid_fini(void *mem, int size)
{
}

/*
 * Initialize ILCC remote node block queue.
 */
static void
ilcc_zone_change(void *tag)
{
	uma_zone_set_max(V_ilcc.cc_zone, maxsockets);
}

/*
 * Initialize an ilcc.
 */
static void
ilcc_init(struct ilcc *ilp)
{
	ILCC_LOCK_INIT(ilp);
#ifdef VIMAGE
	ilp->cc_vnet = curvnet;
#endif

	LIST_INIT(&ilp->cc_lnidlist);
	LIST_INIT(&ilp->cc_ll64list);
	LIST_INIT(&ilp->cc_tnidlist);
	LIST_INIT(&ilp->cc_fnidlist);
	LIST_INIT(&ilp->cc_addrinfolist);
	ilp->cc_nhashbase = hashinit(V_ilnp6_nid_hash_size,
	    M_ILNP6, &ilp->cc_nhashmask);

	ilp->cc_zone = uma_zcreate("ilcc", sizeof(struct foreignnid),
	    NULL, NULL, foreignnid_init, foreignnid_fini, UMA_ALIGN_PTR, 0);
	uma_zone_set_max(ilp->cc_zone, maxsockets);
	uma_zone_set_warning(ilp->cc_zone,
	    "kern.ipc.maxsockets limit reached");
	EVENTHANDLER_REGISTER(maxsockets_change, ilcc_zone_change, NULL,
	    EVENTHANDLER_PRI_ANY);

	/* Add ephemeral NIDs later. */
	ilp->cc_nidpool = 0;

	callout_init_mtx(&ilp->cc_callout, &ilp->cc_lock, 0);
	callout_reset(&ilp->cc_callout, V_ilnp6_prune * hz,
	    ilcc_purge, ilp);
}

static void
vnet_ilcc_init(const void *unused __unused)
{
	ilcc_init(&V_ilcc);
}
VNET_SYSINIT(vnet_ilcc_init, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY,
    vnet_ilcc_init, NULL);

/*
 * Destroy an ilcc.
 */
static void
ilcc_destroy(struct ilcc *ilp)
{
	struct locall64 *llp, *tllp;
	struct localnid *lnp, *tlnp;
	struct foreignnid *np, *tnp;

	callout_drain(&ilp->cc_callout);

	ILCC_LOCK(ilp);
	if (ilp->cc_lul64s != NULL)
		free(ilp->cc_lul64s, M_ILNP6);
	ilp->cc_lul64s = NULL;
	LIST_FOREACH_SAFE(llp, &ilp->cc_ll64list, ll_list, tllp)
		locall64_destroy(ilp, llp);
	LIST_FOREACH_SAFE(lnp, &ilp->cc_lnidlist, ln_list, tlnp)
		localnid_destroy(ilp, lnp);
	LIST_FOREACH_SAFE(np, &ilp->cc_fnidlist, n_list, tnp)
		foreignnid_destroy(ilp, np);
	LIST_FOREACH_SAFE(np, &ilp->cc_tnidlist, n_list, tnp)
		tentativenid_delete(ilp, np);
	LIST_FOREACH_SAFE(np, &ilp->cc_addrinfolist, n_list, tnp)
		addrinfo_delete(ilp, np);
	ILCC_UNLOCK(ilp);

	hashdestroy(ilp->cc_nhashbase, M_ILNP6, ilp->cc_nhashmask);
	uma_zdestroy(ilp->cc_zone);
	ILCC_LOCK_DESTROY(ilp);
}

static void
vnet_ilcc_destroy(const void *unused __unused)
{
	ilcc_destroy(&V_ilcc);
}
VNET_SYSUNINIT(vnet_ilcc_destroy, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY,
    vnet_ilcc_destroy, NULL);

/*
 * Periodic ILCC cleanup.
 * Called with ILCC lock held.
 */
void
ilcc_purge(void *arg)
{
	struct ilcc *ilp = (struct ilcc *)arg;
	struct locall64 *llp, *tllp;
	struct localnid *lnp, *tlnp;
	struct foreignnid *np, *tnp;
	struct foreignl64 *lp, *tlp;
	int localmod = 0;
	int ephs = 0;

	CURVNET_SET(ilp->cc_vnet);

	ILCC_LOCK_ASSERT(ilp);
	
	/*
	 * Expire L64s with stale RAs, and delete addresses and
	 * data associated with expired L64s.
	 */
	LIST_FOREACH_SAFE(llp, &ilp->cc_ll64list, ll_list, tllp) {
		if (llp->ll_flags & ILNP6_LOCAL_EXPIRED) {
			locall64_delete(ilp, llp);
		}
		else if (llp->ll_expire != 0) {
			if (llp->ll_expire < time_uptime &&
			    llp->ll_recv < time_uptime) {
				llp->ll_flags |= ILNP6_LOCAL_EXPIRED;
				localmod = 1;
				locall64_delete(ilp, llp);
			}
		}
	}
	/* Send LU if L64s were expired. */
	if (localmod) {
		lu_output_schedule(ilp);
	}

	/*
	 * Foreign State:
	 * foreignnids are managed by refcounting.
	 * addrinfo should be removed if it is old, or all L64s
	 * have expired.
	 */
	LIST_FOREACH_SAFE(np, &ilp->cc_addrinfolist, n_list, tnp) {
		LIST_FOREACH_SAFE(lp, &np->n_l64list, l_list, tlp) {
			if (lp->l_expire < time_uptime) {
				foreignl64_delete(lp);
				np->l64_idx = 0;

			}
		}
		if (np->n_expire < time_uptime || LIST_EMPTY(&np->n_l64list)) {
			addrinfo_delete(ilp, np);
		}
	}
	LIST_FOREACH_SAFE(np, &ilp->cc_tnidlist, n_list, tnp) {
		LIST_FOREACH_SAFE(lp, &np->n_l64list, l_list, tlp) {
			if (lp->l_expire < time_uptime)
				foreignl64_delete(lp);
		}
		if (np->n_expire < time_uptime || LIST_EMPTY(&np->n_l64list)) {
			tentativenid_delete(ilp, np);
		}
	}
		
	/* Normal remote nodes are handled by refcounting. */
	

	/* Manage NIDs. */
	LIST_FOREACH_SAFE(lnp, &ilp->cc_lnidlist, ln_list, tlnp) {
		if (V_ilnp6_ephemeral_pool < ilp->cc_nidpool &&
		    lnp->ln_flags & ILNP6_LOCAL_EPHEMERAL) {
			/* Don't add a new ephemeral NID when it expired. */
			lnp->ln_flags &= ~ILNP6_LOCAL_EPHEMERAL;
			localnid_age(ilp, lnp);
			ilp->cc_nidpool--;
		}
		if (lnp->ln_flags & ILNP6_LOCAL_AGED &&
		    lnp->ln_refs == 0) {
			/* Remove aged NIDs that are not in use. */
			LIST_REMOVE(lnp, ln_list);
			ILCC_UNLOCK(ilp);

			if (lnp->ln_flags & ILNP6_LOCAL_MANAGED) {
				struct epoch_tracker et;
				struct ifnet *ifp;
				struct in6_ifaddr *in6ifa;
				NET_EPOCH_ENTER(et);
				struct in6_aliasreq ifar = {
					.ifra_lifetime = {0, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME }
				};
				ifar.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
				ifar.ifra_addr.sin6_family = AF_INET6;
				bcopy(&lnp->ln_nid, &ifar.ifra_addr.sin6_addr.s6_addr32[2], sizeof(struct ilnp6_nid));
				ifar.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
				ifar.ifra_prefixmask.sin6_family = AF_INET6;
				memset(&ifar.ifra_prefixmask.sin6_addr, 0xff, 8);

				LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
					ifp = ifnet_byindex(llp->ll_if);
				    bcopy(&llp->ll_l64, &ifar.ifra_addr.sin6_addr, sizeof(struct ilnp6_l64));
					in6ifa = in6ifa_ifpwithaddr(ifp, &ifar.ifra_addr.sin6_addr);
					if (in6ifa) {
						in6_purgeifaddr(in6ifa);
						ifa_free((struct ifaddr*)in6ifa);
					}
				}
				NET_EPOCH_EXIT(et);
			}

			free(lnp, M_ILNP6);
			ILCC_LOCK(ilp);
		}
	}

	/* Increase pool size, or add new NIDs. */
	ilp->cc_nidpool = V_ilnp6_ephemeral_pool;
	LIST_FOREACH(lnp, &ilp->cc_lnidlist, ln_list) {
		if ((lnp->ln_flags & ILNP6_LOCAL_EPHEMERAL) &&
		    !(lnp->ln_flags & ILNP6_LOCAL_USED))
			ephs++;
	}
	for (;ephs < ilp->cc_nidpool; ephs++) {
		localnid_add_ephemeral(ilp);
	}

	callout_reset(&ilp->cc_callout, V_ilnp6_prune * hz,
	    ilcc_purge, arg);

	CURVNET_RESTORE();
}

/*
 * Age a local nid (and delete if there are no references).
 */
static int
localnid_age(struct ilcc *ilp, struct localnid *lnp)
{
#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	lnp->ln_flags |= ILNP6_LOCAL_AGED;
	return (0);
}

/*
 * Generate a new ephemeral NID, based on RFC8981's method.
 *
 * Unlike RFC8981, we can sometimes use NIDs that are already IIDs,
 * sp long as they were previously IPv6 only. They continue to be used
 * as IIDs, but can also be used as NIDs.
 */
static int
localnid_add_ephemeral(struct ilcc *ilp)
{
	struct ilnp6_nid nid;

	do {
		arc4random_buf(&nid, 8);
	}
	while (ILNP6_IS_ADDR_ZERO(&nid) ||
	    (nid.__ui6_addr.__ui6_addr32[0] == 0xFDFFFFFF && nid.__ui6_addr.__ui6_addr32[1] >= 0xFFFFFF80) ||
	    localnid_lookup(ilp, &nid));
	localnid_update_locked(ilp, &nid, V_ilnp6_local_nid_pref, ILNP6_LOCAL_EPHEMERAL|ILNP6_LOCAL_MANAGED);
	ILCC_LOCK(ilp);

	return (0);
}
/*
 * Dereference a local NID entry, and try to delete it if it is
 * aged, or if it an ephemeral NID that has been used.
 */
static int
localnid_dereference(struct ilcc *ilp, struct localnid *lnp)
{
	KASSERT(lnp->ln_refs > 0, ("%s: lnp->ln_refs <= 0", __func__));
	lnp->ln_refs--;
	lnp->ln_flags &= ~ILNP6_LOCAL_ACTIVE;

	if ((lnp->ln_flags & ILNP6_LOCAL_AGED) != 0)
		localnid_age(ilp, lnp);
	if ((lnp->ln_flags & ILNP6_LOCAL_EPHEMERAL) &&
	    (lnp->ln_flags & ILNP6_LOCAL_USED))
		localnid_age(ilp, lnp);
	return (0);
}

/*
 * Destroy a local nid for cleanup.
 */
static void
localnid_destroy(struct ilcc *ilp, struct localnid *lnp)
{
#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_REMOVE(lnp, ln_list);
	free(lnp, M_ILNP6);
}

/*
 * Update a local nid.
 *
 * The locked version unlocks the ILCC.
 */
static int
localnid_update(struct ilcc *ilp, struct ilnp6_nid *nid, uint32_t pref, uint32_t flags)
{
	ILCC_LOCK(ilp);
	return (localnid_update_locked(ilp, nid, pref, flags));
}

static int
localnid_update_locked(struct ilcc *ilp, struct ilnp6_nid *nid, uint32_t pref, uint32_t flags)
{
	struct localnid *lnp, *p;
	struct locall64 *llp;
	uint32_t previous;
	int isnew = 0;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	lnp = localnid_lookup(ilp, nid);
	if (lnp == NULL) {
		lnp = malloc(sizeof(struct localnid), M_ILNP6, M_NOWAIT);
		if (lnp == NULL) {
			ILCC_UNLOCK(ilp);
			return (ENOMEM);
		}
		bzero(lnp, sizeof(struct localnid));
		ILNP6_NID_COPY(nid, &lnp->ln_nid);
		lnp->ln_pref = pref;
		lnp->ln_flags = flags;
		isnew = 1;
	}
	else {
		lnp->ln_flags = flags;
		/* Skip reordering if the order is unchanged. */
		if (lnp->ln_pref == pref) {
			ILCC_UNLOCK(ilp);
			return (0);
		}

		previous = lnp->ln_pref;
		lnp->ln_pref = pref;
		if (previous < pref) {
			p = LIST_NEXT(lnp, ln_list);
			if ((p == NULL) || (p->ln_pref >= pref)) {
				ILCC_UNLOCK(ilp);
				return (0);
			}
			LIST_REMOVE(lnp, ln_list);
		}
		else {
			p = LIST_FIRST(&ilp->cc_lnidlist);
			if (p == lnp) {
				ILCC_UNLOCK(ilp);
				return (0);
			}
			LIST_REMOVE(lnp, ln_list);
		}
	}

	if (LIST_EMPTY(&ilp->cc_lnidlist)) {
		LIST_INSERT_HEAD(&ilp->cc_lnidlist, lnp, ln_list);
	}
	else {
		LIST_FOREACH(p, &ilp->cc_lnidlist, ln_list) {
			if (p->ln_pref > pref) {
				LIST_INSERT_BEFORE(p, lnp, ln_list);
				break;
			}
			/* reach the end. */
			if (LIST_NEXT(p, ln_list) == NULL) {
				LIST_INSERT_AFTER(p, lnp, ln_list);
				break;
			}
		}
	}

	/*
	 * Ensure new NIDs are added to interfaces.
	 */
	if (isnew) {
		struct epoch_tracker et;
		struct ifnet *ifp;
		struct in6_ifaddr *in6ifa;
		int lcount = 0, offset = 0;
		u_short *ll_ifs;
		struct ilnp6_l64 *ll_l64s;

		/*
		 * Most of the aliasrequest stays the same, so just reuse it.
		 */
		struct in6_aliasreq ifar = {
			.ifra_lifetime = {0, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME }
		};
		ifar.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifar.ifra_addr.sin6_family = AF_INET6;
		bcopy(&lnp->ln_nid, &ifar.ifra_addr.sin6_addr.s6_addr32[2], sizeof(struct ilnp6_nid));
		ifar.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
		ifar.ifra_prefixmask.sin6_family = AF_INET6;
		memset(&ifar.ifra_prefixmask.sin6_addr, 0xff, 8);

		/*
		 * Can't do DAD with ILCC locked, so copy data and unlock.
		 */
		LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
			lcount++;
		}
		ll_l64s = malloc(sizeof(struct ilnp6_l64) * lcount, M_ILNP6, M_NOWAIT);
		ll_ifs = malloc(sizeof(struct ilnp6_l64) * lcount, M_ILNP6, M_NOWAIT);
		LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
	    bcopy(&llp->ll_l64, &ll_l64s[offset], sizeof(struct ilnp6_l64));
			ll_ifs[offset] = llp->ll_if;
			offset++;
		}

		/*
		 * Perform the updates.
		 */
		ILCC_UNLOCK(&V_ilcc);
		NET_EPOCH_ENTER(et);
		for (offset = 0; offset < lcount; offset++) {
			ifp = ifnet_byindex(ll_ifs[offset]);
		    bcopy(&ll_l64s[offset], &ifar.ifra_addr.sin6_addr, sizeof(struct ilnp6_l64));
			in6ifa = in6ifa_ifpwithaddr(ifp, &ifar.ifra_addr.sin6_addr);

			/* If we added it, update ILCC flags. */
			if (in6ifa == NULL) {
				ILCC_LOCK(ilp);
				if ((lnp = localnid_lookup(ilp, nid)) != NULL)
					lnp->ln_flags |= ILNP6_LOCAL_MANAGED;
				ILCC_UNLOCK(ilp);
			}
			in6_update_ifa(
				ifp,
				&ifar,
				in6ifa,
				0
			);
			if (in6ifa) {
				ifa_free((struct ifaddr*)in6ifa);
			}
		}
		NET_EPOCH_EXIT(et);

		free(ll_l64s, M_ILNP6);
		free(ll_ifs, M_ILNP6);
	}
	else {
		ILCC_UNLOCK(&V_ilcc);
	}
	return (0);
}

/*
 * Lookup a local nid.
 */
static struct localnid *
localnid_lookup(struct ilcc *ilp, const struct ilnp6_nid *nid)
{
	struct localnid *lnp;
#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_FOREACH(lnp, &ilp->cc_lnidlist, ln_list) {
		if (ILNP6_ARE_NID_EQUAL(nid, &lnp->ln_nid))
			break;
	}
	return (lnp);
}

/*
 * Destroy a local locator.
 */
static void
locall64_destroy(struct ilcc *ilp, struct locall64 *llp)
{
#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_REMOVE(llp, ll_list);
	free(llp, M_ILNP6);
}

/*
 * Delete a local locator, and remove corresponding ILVs.
 */
static int
locall64_delete(struct ilcc *ilp, struct locall64 *llp)
{
	struct locall64 *lp;
	struct localnid *lnp;
	struct epoch_tracker et;
	struct ifnet *ifp;
	struct in6_ifaddr *in6ifa;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_REMOVE(llp, ll_list);
	NET_EPOCH_ENTER(et);
	struct in6_aliasreq ifar = { 
		.ifra_lifetime = {0, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME }
	};
	ifar.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifar.ifra_addr.sin6_family = AF_INET6;
	bcopy(&llp->ll_l64, &ifar.ifra_addr.sin6_addr, sizeof(struct ilnp6_l64));
	ifar.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifar.ifra_prefixmask.sin6_family = AF_INET6;
	memset(&ifar.ifra_prefixmask.sin6_addr, 0xff, 8);
	ifp = ifnet_byindex(llp->ll_if);

	LIST_FOREACH(lnp, &ilp->cc_lnidlist, ln_list) {
		if (lnp->ln_flags & ILNP6_LOCAL_MANAGED) {
		  bcopy(&lnp->ln_nid, &ifar.ifra_addr.sin6_addr.s6_addr32[2], sizeof(struct ilnp6_nid));
			in6ifa = in6ifa_ifpwithaddr(ifp, &ifar.ifra_addr.sin6_addr);
			if (in6ifa) {
				in6_purgeifaddr(in6ifa);
				ifa_free((struct ifaddr*)in6ifa);
			}
		}
	}
	NET_EPOCH_EXIT(et);
	free(llp, M_ILNP6);
	/* Reset local l64 scores. */
	LIST_FOREACH(lp, &ilp->cc_ll64list, ll_list)
		lp->ll_score = 0;
	return (0);
}

/*
 * Create a new local locator, or update it if it exists.
 *
 * Also adds all ILVs to the interface.
 */
static int
locall64_update(struct ilcc *ilp, const struct ilnp6_l64 *l64, const struct in6_addr *gw,
    uint32_t pref, time_t expire, u_short iface)
{
	struct locall64 *llp, *p;
	uint32_t previous;
	int isnew = 0;

	ILCC_LOCK(ilp);
	llp = locall64_lookup(ilp, l64);
	if (llp == NULL) {
		llp = malloc(sizeof(struct locall64), M_ILNP6, M_NOWAIT);
		if (llp == NULL) {
			ILCC_UNLOCK(ilp);
			return (ENOMEM);
		}
		bzero(llp, sizeof(struct locall64));
		ILNP6_L64_COPY(l64, &llp->ll_l64);
		bcopy(gw, &llp->ll_gw, sizeof(struct in6_addr));
		llp->ll_expire = expire;
		llp->ll_if = iface;
		llp->ll_score = 0;
		/* Reset local l64 scores. */
		LIST_FOREACH(p, &ilp->cc_ll64list, ll_list)
			p->ll_score = 0;
		isnew = 1;
	}
	else {
		/* Only update TTL if it is not infinite. */
		if (llp->ll_expire != 0)
			llp->ll_expire = expire;
		llp->ll_flags &= ~ILNP6_LOCAL_EXPIRED;
		llp->ll_if = iface;

		/* Always update gateway. */
		bcopy(gw, &llp->ll_gw, sizeof(struct in6_addr));

		/* Only reorder list if necessary. */
		previous = llp->ll_pref;
		if (previous == pref) {
			ILCC_UNLOCK(ilp);
			return (0);
		}
		llp->ll_pref = pref;

		if (previous < pref) {
			p = LIST_NEXT(llp, ll_list);
			if ((p == NULL) || (p->ll_pref >= pref)) {
				ILCC_UNLOCK(ilp);
				return (0);
			}
			LIST_REMOVE(llp, ll_list);
		}
		else {
			p = LIST_FIRST(&ilp->cc_ll64list);
			if (p == llp) {
				ILCC_UNLOCK(ilp);
				return (0);
			}
			LIST_REMOVE(llp, ll_list);
		}
	}

	/* Insert into ordered list. */
	if (LIST_EMPTY(&ilp->cc_ll64list)) {
		LIST_INSERT_HEAD(&ilp->cc_ll64list, llp, ll_list);
	}
	else {
		LIST_FOREACH(p, &ilp->cc_ll64list, ll_list) {
			if (p->ll_pref > pref) {
				LIST_INSERT_BEFORE(p, llp, ll_list);
				break;
			}
			/* reach the end. */
			if (LIST_NEXT(p, ll_list) == NULL) {
				LIST_INSERT_AFTER(p, llp, ll_list);
				break;
			}
		}
	}
	/* Send LUs if something changed. */
	lu_output_schedule(ilp);

	/* Add ILVs to interface. */
	if (isnew) {
		struct epoch_tracker et;
		struct ifnet *ifp;
		struct in6_ifaddr *in6ifa;
		int ncount = 0, offset = 0;
		struct ilnp6_nid *ln_nids;
		struct localnid *lnp;

		/*
		 * Most of the aliasrequest stays the same, so just reuse it.
		 */
		struct in6_aliasreq ifar = {
			.ifra_lifetime = {0, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME }
		};
		ifar.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifar.ifra_addr.sin6_family = AF_INET6;
		bcopy(&llp->ll_l64, &ifar.ifra_addr.sin6_addr, sizeof(struct ilnp6_l64));
		ifar.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
		ifar.ifra_prefixmask.sin6_family = AF_INET6;
		memset(&ifar.ifra_prefixmask.sin6_addr, 0xff, 8);

		/*
		 * Can't do DAD with ILCC locked, so copy data and unlock.
		 */
		LIST_FOREACH(lnp, &ilp->cc_lnidlist, ln_list) {
			ncount++;
		}
		ln_nids = malloc(sizeof(struct ilnp6_nid) * ncount, M_ILNP6, M_NOWAIT);
		LIST_FOREACH(lnp, &ilp->cc_lnidlist, ln_list) {
	    bcopy(&lnp->ln_nid, &ln_nids[offset], sizeof(struct ilnp6_nid));
			offset++;
		}
		/*
		 * Perform the updates.
		 */
		ILCC_UNLOCK(&V_ilcc);
		NET_EPOCH_ENTER(et);
		ifp = ifnet_byindex(iface);
		for (offset = 0; offset < ncount; offset++) {
		  bcopy(&ln_nids[offset], &ifar.ifra_addr.sin6_addr.s6_addr32[2], sizeof(struct ilnp6_nid));
			in6ifa = in6ifa_ifpwithaddr(ifp, &ifar.ifra_addr.sin6_addr);

			/* If we added it, update ILCC flags. */
			if (in6ifa == NULL) {
				ILCC_LOCK(ilp);
				if ((lnp = localnid_lookup(ilp, &ln_nids[offset])) != NULL)
					lnp->ln_flags |= ILNP6_LOCAL_MANAGED;
				ILCC_UNLOCK(ilp);
			}
			in6_update_ifa(
				ifp,
				&ifar,
				in6ifa,
				0
			);
			if (in6ifa) {
				ifa_free((struct ifaddr*)in6ifa);
			}
		}
		NET_EPOCH_EXIT(et);

		free(ln_nids, M_ILNP6);
	}
	else {
		ILCC_UNLOCK(&V_ilcc);
	}
	return (0);
}

/*
 * Lookup a local L64.
 * Caller must own the ilcc lock.
 */
static struct locall64 *
locall64_lookup(struct ilcc *ilp, const struct ilnp6_l64 *l64)
{
	struct locall64 *llp;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
		if (ILNP6_ARE_L64_EQUAL(l64, &llp->ll_l64))
			break;
	}
	return (llp);
}

/*
 * Delete a foreign L64 entry.
 */
int
foreignl64_delete(struct foreignl64 *lp)
{
	LIST_REMOVE(lp, l_list);
	free(lp, M_ILNP6);
	return (0);
}


/*
 * Handle an error for a foreign L64 entry.
 */
int
ilnp6_unreachable_l64(struct ilcc * ilp, struct inpcb * inp, struct in6_addr * dst)
{
	struct ilnp6_ilv *filv;
	struct foreignl64 *lp;
	struct foreignnid *np;

	if (!V_ilnp6_enable || inp == NULL || dst == NULL)
		return (-1);
	filv = (struct ilnp6_ilv *) dst;

	ILCC_LOCK(ilp);
	if ((np = foreignnid_lookup_inpcb(inp)) == NULL) {
		ILCC_UNLOCK(ilp);
		return (-1);
	}

	lp = foreignl64_lookup(np, &filv->ilv_l64);
	if (lp != NULL) {
		foreignl64_delete(lp);
		ILCC_UNLOCK(ilp);
		return (0);
	}
	ILCC_UNLOCK(ilp);
	return (-1);

}

/*
 * Create or update a remote L64 entry for a remote NID.
 */
int
foreignl64_update(struct foreignnid *np, const struct ilnp6_l64 *l64, uint32_t pref, time_t expire)
{
	struct foreignl64 *p, *lp;
	uint32_t previous;

	lp = foreignl64_lookup(np, l64);
	
	if (lp == NULL) {
		lp = malloc(sizeof(struct foreignl64), M_ILNP6, M_NOWAIT);
		if (lp == NULL)
			return (ENOMEM);
		bzero(lp, sizeof(struct foreignl64));
		ILNP6_L64_COPY(l64, &lp->l_l64);
		lp->l_expire = expire;
		lp->l_pref = pref;
	}
	else {
		lp->l_expire = expire;

		/* Avoid reordering list if possible. */
		previous = lp->l_pref;
		if (previous == pref)
			return (0);
		lp->l_pref = pref;
		
		if (previous < pref) {
			p = LIST_NEXT(lp, l_list);
			if ((p == NULL) || (p->l_pref >= pref))
				return (0);
			LIST_REMOVE(lp, l_list);
		}
		else {
			p = LIST_FIRST(&np->n_l64list);
			if (p == lp)
				return (0);
			LIST_REMOVE(lp, l_list);
		}
	}

	if (LIST_EMPTY(&np->n_l64list)) {
		LIST_INSERT_HEAD(&np->n_l64list, lp, l_list);
		return (0);
	}
	LIST_FOREACH(p, &np->n_l64list, l_list) {
		/* Insert after equally prefered L64s. */
		if (p->l_pref > lp->l_pref) {
			LIST_INSERT_BEFORE(p, lp, l_list);
			break;
		}
		if (LIST_NEXT(p, l_list) == NULL) {
			LIST_INSERT_AFTER(p, lp, l_list);
			break;
		}
	}
	return (0);
}

/*
 * Look up an L64 in a foreign NID entry.
 */
struct foreignl64 *
foreignl64_lookup(struct foreignnid *np, const struct ilnp6_l64 *l64)
{
	struct foreignl64 *lp;
	LIST_FOREACH(lp, &np->n_l64list, l_list) {
		if (ILNP6_ARE_L64_EQUAL(&lp->l_l64, l64))
			break;
	}
	return (lp);
}

/*
 * Destroy a foreign NID entry.
 */
static int
foreignnid_destroy(struct ilcc *ilp, struct foreignnid *np)
{
	struct foreignl64 *lp, *tlp;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	callout_stop(&np->n_lucallout);

	LIST_REMOVE(np, n_list);
	LIST_REMOVE(np, n_nidhash);

	LIST_FOREACH_SAFE(lp, &np->n_l64list, l_list, tlp)
		foreignl64_delete(lp);

	uma_zfree(ilp->cc_zone, np);
	return (0);
}

/*
 * Delete a foreign NID entry.
 */
static int
foreignnid_delete(struct ilcc *ilp, struct foreignnid *np)
{
	struct foreignl64 *lp, *tlp;
	struct localnid *lnp;
#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	np->n_refcount--;
	if (np->n_refcount != 0)
		return (0);

	callout_stop(&np->n_lucallout);

	LIST_REMOVE(np, n_list);
	LIST_REMOVE(np, n_nidhash);

	LIST_FOREACH_SAFE(lp, &np->n_l64list, l_list, tlp)
		foreignl64_delete(lp);

	if ((lnp = localnid_lookup(ilp, &np->n_lnid)) != NULL)
		localnid_dereference(ilp, lnp);
	
	uma_zfree(ilp->cc_zone, np);
	return (0);
}

/*
 * Connect to an ILCC node. 
 */
static int
foreignnid_update(struct ilcc *ilp, struct foreignnid **npp, const struct ilnp6_nid *nid,
    const struct ilnp6_l64 *l64, const struct ilnp6_nid *lnid)
{
	struct foreignl64 *lp;
	struct localnid *lnp;
	struct foreignnid *np, *addrinfo;
	int len, err;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif

	if ((lnp = localnid_lookup(ilp, lnid)) == NULL)
		return (EADDRNOTAVAIL);
	/*
	 * Look for an existing node to use.
	 *
	 * TODO: avoid reusing LIVE nodes, as we must regenerate unique nonces.
	 * XXX: if we commit to bidirectional nonces, we don't need LOCAL nodes?
	 *
	 * Case 1: There is already a LIVE node to use
	 * Case 2: There is already a LOCAL node waiting for a
	 * 	foreign nonce
	 * Case 3: There is a TENTATIVE node waiting for a PCB
	 * Case 4: There is ADDRINFO from which to make the node
	 * Case 5: Fall back to IPv6
	 *
	 */

	/* Case 1 or 2: local or live */
	np = foreignnid_lookup(ilp, nid, l64, lnid);

	/* Case 3: tentative */
	if (np == NULL) {
		LIST_FOREACH(np, &ilp->cc_tnidlist, n_list) {
			if (ILNP6_ARE_NID_EQUAL(&np->n_nid, nid) &&
			    ILNP6_ARE_NID_EQUAL(&np->n_lnid, lnid) &&
			    (foreignl64_lookup(np, l64) != NULL)) {
				break;
			}
		}
		if (np != NULL) {
			/* Upgrade from tentative to live. */
			LIST_REMOVE(np, n_list);
			LIST_INSERT_HEAD(&ilp->cc_fnidlist, np, n_list);
			LIST_INSERT_HEAD(ILNP6NID_HASH_BUCKET(ilp, nid), np, n_nidhash);
		}
	}

	/* Case 4: Create entry from addrinfo. */
	if (np == NULL) {
		/* Case 5: fall back to IPv6 */
		addrinfo = addrinfo_lookup(ilp, nid, l64);
		if (addrinfo == NULL)
			return (EADDRNOTAVAIL);

		np = uma_zalloc(ilp->cc_zone, M_NOWAIT);
		if (np == NULL)
			return (ENOMEM);
		bzero(np, sizeof(struct foreignnid));

		LIST_INSERT_HEAD(&ilp->cc_fnidlist, np, n_list);
		LIST_INSERT_HEAD(ILNP6NID_HASH_BUCKET(ilp, nid), np, n_nidhash); 
		np->n_ilcc = ilp;

		ILNP6_NID_COPY(nid, &np->n_nid);
		LIST_INIT(&np->n_l64list);
		ILNP6_NID_COPY(lnid, &np->n_lnid);
		len = V_ilnp6_nonce_size;
		np->n_lnonce.ion_opt.ip6o_type = IP6OPT_ILNP_NONCE;
		np->n_lnonce.ion_opt.ip6o_len = len;
		arc4random_buf(np->n_lnonce.ion_nonce, len);

		np->n_expire = addrinfo->n_expire;
		if (locall64_select(ilp, NULL) == NULL) {
			foreignnid_destroy(ilp, np);
			return (EADDRNOTAVAIL);
		}
		LIST_FOREACH(lp, &addrinfo->n_l64list, l_list) {
			err = foreignl64_update(np, &lp->l_l64, lp->l_pref, lp->l_expire);
			if (err != 0) {
				/*
				 * XXX: do not try to delete the local entry,
				 * as we never actually touched it.
				 */
				foreignnid_destroy(ilp, np);
				return (err);
			}
		}
		lnp->ln_refs++;
		if (lnp->ln_flags & ILNP6_LOCAL_EPHEMERAL) {
			lnp->ln_flags |= ILNP6_LOCAL_ACTIVE;
		}
		if ((addrinfo->n_flags & ILNP6_FOREIGN_NONCE_SET) != 0) {
			ILNP6_NONCE_COPY(&addrinfo->n_rnonce, &np->n_rnonce);
			np->n_flags |= ILNP6_FOREIGN_NONCE_SET;
		}
		
		np->n_luretrans = 0;
		callout_init_mtx(&np->n_lucallout, &ilp->cc_lock, 0);
	}
	np->l64_idx=0;
	*npp = np;
	return (0);
}

/*
 * Search for a remote node for an I-LV and source NID.
 */
static struct foreignnid *
foreignnid_lookup(struct ilcc *ilp, const struct ilnp6_nid *fnid,
    const struct ilnp6_l64 *fl64, const struct ilnp6_nid *lnid)
{
	struct foreignnid *np;
#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_FOREACH(np, ILNP6NID_HASH_BUCKET(ilp, fnid), n_nidhash) {
		if (((np->n_flags & ILNP6_FOREIGN_ADDRINFO) == 0) &&
		    (ILNP6_ARE_NID_EQUAL(fnid, &np->n_nid)) &&
				(foreignl64_lookup(np, fl64) != NULL) &&
		    (ILNP6_ARE_NID_EQUAL(lnid, &np->n_lnid))) {
			break;
		}
	}
	return (np);
}

/* 
 * Get the ilcc node reference by the inp.
 */
static struct foreignnid *
foreignnid_lookup_inpcb(struct inpcb *inp)
{
	if (inp && (inp->inp_flags2 & INP_ILNP6_CONNECTED) != 0)
		return (inp->inp_np);
	return (NULL);
}

/*
 * Look up a remote node entry based on NID and nonce. Nonce must be
 * set (see the flag), and match.
 */
static struct foreignnid *
foreignnid_lookup_nonce(struct ilcc *ilp, const struct ilnp6_nid *nid,
    const struct ilnp_nonce_opt *nonce)
{
	struct foreignnid *np;
#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_FOREACH(np, ILNP6NID_HASH_BUCKET(ilp, nid), n_nidhash) {
		if (((np->n_flags & ILNP6_FOREIGN_ADDRINFO) == 0) &&
		    (ILNP6_ARE_NID_EQUAL(nid, &np->n_nid)) &&
		    ((np->n_flags & ILNP6_FOREIGN_NONCE_SET) != 0) &&
		    (ILNP6_ARE_NONCE_EQUAL(nonce, &np->n_rnonce))) {
			break;
		}
	}
	return (np);
}

/*
 * Delete an addrinfo entry.
 */
static int
addrinfo_delete(struct ilcc *ilp, struct foreignnid *np)
{
	struct foreignl64 *lp, *tlp;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	callout_stop(&np->n_lucallout);

	LIST_REMOVE(np, n_list);
	LIST_REMOVE(np, n_nidhash);

	LIST_FOREACH_SAFE(lp, &np->n_l64list, l_list, tlp)
		foreignl64_delete(lp);

	uma_zfree(ilp->cc_zone, np);
	return (0);
}

/* 
 * Create or update addrinfo.
 */
static int
addrinfo_update(struct ilcc *ilp, const struct ilnp6_ilv *ilv,
    time_t nidexpire, time_t l64expire, uint32_t l64pref)
{
	struct foreignnid *np;
	int err;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	/* Look up addrinfo, ignoring L64. */
	LIST_FOREACH(np, ILNP6NID_HASH_BUCKET(ilp, &ilv->ilv_nid), n_nidhash) {
		if ((np->n_flags & ILNP6_FOREIGN_ADDRINFO) != 0 &&
		    ILNP6_ARE_NID_EQUAL(&ilv->ilv_nid, &np->n_nid))
			break;
	}

	/* Create a new entry if needed. */
	if (np == NULL) {
		np = uma_zalloc(ilp->cc_zone, M_NOWAIT);
		if (np == NULL)
			return (ENOMEM);
		bzero(np, sizeof(struct foreignnid));

		/* Mark as addrinfo, not remote node. */
		np->n_flags |= ILNP6_FOREIGN_ADDRINFO;
		LIST_INSERT_HEAD(&ilp->cc_addrinfolist, np, n_list);
		LIST_INSERT_HEAD(ILNP6NID_HASH_BUCKET(ilp, &ilv->ilv_nid), np, n_nidhash);
		np->n_ilcc = ilp;
		ILNP6_NID_COPY(&ilv->ilv_nid, &np->n_nid);
		LIST_INIT(&np->n_l64list);
	}
	np->n_expire = nidexpire;

	/* Update the L64 entry. */
	err = foreignl64_update(np, &ilv->ilv_l64, l64pref, l64expire);
	return (err);
}

/*
 * Look up a addrinfo entry by ILV.
 */
static struct foreignnid *
addrinfo_lookup(struct ilcc *ilp, const struct ilnp6_nid *fnid, const struct ilnp6_l64 *fl64)
{
	struct foreignnid *np;
#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_FOREACH(np, ILNP6NID_HASH_BUCKET(ilp, fnid), n_nidhash) {
		if (((np->n_flags & ILNP6_FOREIGN_ADDRINFO) != 0) &&
		    (ILNP6_ARE_NID_EQUAL(fnid, &np->n_nid)) &&
		    (foreignl64_lookup(np, fl64) != NULL)) {
			break;
		}
	}
	return (np);
}

/*
 * Delete an tentative entry.
 */
static int
tentativenid_delete(struct ilcc *ilp, struct foreignnid *np)
{
	struct foreignl64 *lp, *tlp;
	struct localnid *lnp;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_REMOVE(np, n_list);

	LIST_FOREACH_SAFE(lp, &np->n_l64list, l_list, tlp)
		foreignl64_delete(lp);

	if ((lnp = localnid_lookup(ilp, &np->n_lnid)) != NULL)
		localnid_dereference(ilp, lnp);

	uma_zfree(ilp->cc_zone, np);
	return (0);
}

/* 
 * Create or update a tentative foreign NID entry.
 */
static int
tentativenid_update(struct ilcc *ilp, const struct ilnp6_nid *nid,
    const struct ilnp6_l64 *l64, const struct ilnp6_nid *lnid, struct ilnp_nonce_opt *nonce)
{
	struct localnid *lnp;
	struct foreignnid *np;
	// size_t len;
	int err;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	/* Check if a tentative entry alreay exists. */
	// TODO: this should use the nonce, not l64
	LIST_FOREACH(np, &ilp->cc_tnidlist, n_list) {
		if (ILNP6_ARE_NID_EQUAL(&np->n_nid, nid) &&
		    ILNP6_ARE_NID_EQUAL(&np->n_lnid, lnid) &&
		    (foreignl64_lookup(np, l64) != NULL)) {
			break;
		}
	}

	/* Create a new entry if needed. */
	if (np == NULL) {
		np = uma_zalloc(ilp->cc_zone, M_NOWAIT);
		if (np == NULL)
			return (ENOMEM);
		bzero(np, sizeof(struct foreignnid));

		LIST_INSERT_HEAD(&ilp->cc_tnidlist, np, n_list);
		np->n_ilcc = ilp;
		ILNP6_NID_COPY(nid, &np->n_nid);
		LIST_INIT(&np->n_l64list);
		ILNP6_NID_COPY(lnid, &np->n_lnid);
		
		lnp = localnid_lookup(&V_ilcc, lnid);
		if (lnp == NULL) {
			foreignnid_destroy(ilp, np);
			return (0);
		}
		lnp->ln_refs++;

		/* 
		 * Don't generate a new local nonce, as we'll use the remote's
		 * in both directions.
		 */ 
		// len = V_ilnp6_nonce_size;
		// np->n_lnonce.ion_opt.ip6o_type = IP6OPT_ILNP_NONCE;
		// np->n_lnonce.ion_opt.ip6o_len = len;
		// arc4random_buf(np->n_lnonce.ion_nonce, len);

		np->n_luretrans = 0;
		callout_init_mtx(&np->n_lucallout, &ilp->cc_lock, 0);
	}
	np->n_expire = time_uptime + V_ilnp6_on_input_ttl;
	/*
	 * XXX: there is a race to set the nonce, as a new packet
	 * may be recieved before the PCB connects. In this case,
	 * we should update the nonce, as the old value may be stale.
	 */
	ILNP6_NONCE_COPY(nonce, &np->n_rnonce);
	np->n_flags |= ILNP6_FOREIGN_NONCE_SET;

	/* Update the L64 entry. */
	err = foreignl64_update(np, l64, V_ilnp6_on_input_pref,
	    time_uptime + V_ilnp6_on_input_ttl);
	return (err);
}

/*
 * Add/update a local L64 from an LU.
 * TODO: TTL should not be higher than what the RA says
 */
int
ilnp6_ra_input(struct in6_addr *prefix, struct in6_addr *gw, u_char plen, uint32_t pltime, struct ifnet *ifp)
{
	int err;

	if (!V_ilnp6_enable)
		return (0);

	err = locall64_update(&V_ilcc, ILNP6_IPV6_TO_L64(prefix), gw, V_ilnp6_local_l64_pref,
	    time_uptime + V_ilnp6_local_l64_ttl, ifp->if_index);
	return (err);
}

/*
 * ILNP nonce option input processing.
 */
int
ilnp6_nonce_input(struct ip6_dest *dstopts, uint8_t *optp, struct mbuf *m) {
	struct foreignnid *np;
	struct m_tag *mtag;
	struct ip6_hdr *ip6;
	struct locall64 *llp;
	struct ilnp_nonce_opt *nonce;
	int optlen = *(optp + 1) + 2;

	/* Check ILNL6 is enabled and validate header order and nonce size. */
	nonce = (struct ilnp_nonce_opt *) optp;
	if (!V_ilnp6_enable ||
	    dstopts->ip6d_nxt == IPPROTO_ROUTING ||
	    ILNP6_NONCE_OPTLEN(nonce) > sizeof(struct ilnp_nonce_opt)) {
		optlen = ip6_unknown_opt(optp, m, optp - mtod(m, uint8_t *));
		if (optlen == -1)
			return (optlen);
		return (optlen + 2);
	}

	ILCC_LOCK(&V_ilcc);
	ip6 = mtod(m, struct ip6_hdr *);
	
	/* Update dst L64's 'last used' time */
	llp = locall64_lookup(&V_ilcc, ILNP6_IPV6_TO_L64(&ip6->ip6_dst));
	if (llp != NULL) {
		llp->ll_recv = time_uptime + V_ilnp6_local_l64_ttl;
		llp->ll_flags &= ~ILNP6_LOCAL_EXPIRED;
	}

	/* Check dst NID supports ILNP. */
	if (localnid_lookup(&V_ilcc, ILNP6_IPV6_TO_NID(&ip6->ip6_dst)) == NULL) {
		ILCC_UNLOCK(&V_ilcc);
		optlen = ip6_unknown_opt(optp, m, optp - mtod(m, uint8_t *));
		if (optlen == -1)
			return (optlen);
		return (optlen + 2);
	}

	/*
	 * We must store the nonce in a foreignnid entry. Try the following:
	 *
	 * 1. Use the nonce for a lookup to check if we have already seen it
	 * 2. Check for an existing node for the ILV. If the nonce is unset,
	 * 	set it, otherwise assume it is spoofed and ignore it. NOTE:
	 * 	it is possible that it is a new connection from that node and
	 * 	have a stale value. If so, our stale value will soon be discarded
	 * 	and the connection can be established.
	 * 3. Create a new addrinfo entry based on the remote node. Use this to
	 * 	establish the nonces for an inbound connection
	 */

	/* Case 1 */
	np = foreignnid_lookup_nonce(&V_ilcc, ILNP6_IPV6_TO_NID(&ip6->ip6_src), nonce);
	if (np == NULL) {
		/* Case 2 */
		np = foreignnid_lookup(&V_ilcc, ILNP6_IPV6_TO_NID(&ip6->ip6_src),
		    ILNP6_IPV6_TO_L64(&ip6->ip6_src), ILNP6_IPV6_TO_NID(&ip6->ip6_dst));
		if (np != NULL) {
			if ((np->n_flags & ILNP6_FOREIGN_NONCE_SET) == 0) {
				ILNP6_NONCE_COPY(nonce, &np->n_rnonce);
				np->n_flags |= ILNP6_FOREIGN_NONCE_SET;
			}
		}
		else {
			/* Case 3 */
			tentativenid_update(&V_ilcc, ILNP6_IPV6_TO_NID(&ip6->ip6_src),
			    ILNP6_IPV6_TO_L64(&ip6->ip6_src), ILNP6_IPV6_TO_NID(&ip6->ip6_dst),
			    nonce);
		}
	}
	ILCC_UNLOCK(&V_ilcc);

	/* Save the nonce in a mbuf tag */
	mtag = m_tag_get(PACKET_TAG_IPOPTIONS, optlen, M_NOWAIT);
	if (mtag == NULL)
		return (-1);
	bcopy(nonce, mtag + 1, optlen);
	m_tag_prepend(m, mtag);
	return (optlen);
}

/*
 * Find nonce offsets in destination options, or 0 if missing.
 */
int
ilnp6_dstopts_nonce_offset(struct ip6_dest *dstopts, int off) {
	int dstoptlen, optlen;
	uint8_t *opt;

	dstoptlen = (dstopts->ip6d_len + 1) << 3;
	off += sizeof(struct ip6_dest);
	dstoptlen -= sizeof(struct ip6_dest);
	opt = (uint8_t *)dstopts + sizeof(struct ip6_dest);

	/* Parse destination header. */
	while (dstoptlen > 0) {
		/* Get option length. */
		if (*opt == IP6OPT_PAD1)
			optlen = 1;
		else
			optlen = *(opt + 1) + 2;
		/* Check overflow. */
		if (optlen > dstoptlen)
			return (0);
		/* Return if the nonce option was found. */
		if (*opt == IP6OPT_ILNP_NONCE)
			return (off);
		/* Go to the next option. */
		off += optlen;
		dstoptlen -= optlen;
		opt += optlen;
	}
	return (0);
}

/*
 * ILNP paramprob option input handling. may free mbuf.
 */
void
ilnp6_paramprob_input(struct mbuf **mp, int off, int icmp6len)
{
	struct mbuf *m = *mp;
	struct foreignnid *np;
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *nip6;
	struct ip6_ext *eh;
	uint8_t nxt, *optp;
	uint32_t eoff;
	int nioff, dstoptlen, optlen;

	if (!V_ilnp6_enable)
		return;

	icmp6 = (struct icmp6_hdr *)(mtod(m, caddr_t) + off);
	eoff = ntohl(icmp6->icmp6_pptr);
	off += sizeof(struct icmp6_hdr);
	nioff = off;
	
	/* Make the packet availible from the mbuf. */
	if (m->m_len < off + sizeof(struct ip6_hdr)) {
		m = m_pullup(m, off + sizeof(struct ip6_hdr));
		*mp = m;
		if (m == NULL)
			return;
	}
	nip6 = (struct ip6_hdr *)(mtod(m, caddr_t) + nioff);
	off += sizeof(struct ip6_hdr);
	nxt = nip6->ip6_nxt;

	while (1) {
		struct ip6_frag *fh;

		eh = NULL;
		switch (nxt) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_AH:
		case IPPROTO_DSTOPTS:
			if (m->m_len < off + sizeof(struct ip6_ext)) {
				m = m_pullup(m,	off + sizeof(struct ip6_ext));
				*mp = m;
				if (m == NULL)
					return;
			}
			eh = (struct ip6_ext *)(mtod(m, caddr_t) + off);
			if (nxt == IPPROTO_DSTOPTS)
				break;
			else if (nxt == IPPROTO_AH)
				off += (eh->ip6e_len + 2) << 2;
			else
				off += (eh->ip6e_len + 1) << 3;
			nxt = eh->ip6e_nxt;
			eh = NULL;
			break;

		case IPPROTO_FRAGMENT:
			if (m->m_len < off + sizeof(struct ip6_frag)) {
				m = m_pullup(m, off + sizeof(struct ip6_frag));
				*mp = m;
				if (m == NULL)
					return;
			}
			fh = (struct ip6_frag *)(mtod(m, caddr_t) + off);
			/* Give up if not the first fragment. */
			if (fh->ip6f_offlg & IP6F_OFF_MASK)
				return;
			off += sizeof(struct ip6_frag);
			nxt = fh->ip6f_nxt;
			break;

		default:
			return;
		}
		if ((nxt == IPPROTO_DSTOPTS) && (eh != NULL))
			break;
	}
	if ((nxt != IPPROTO_DSTOPTS) || (eh == NULL))
		return;
	dstoptlen = (eh->ip6e_len + 1) << 3;
	if (m->m_len < off + dstoptlen) {
		m = m_pullup(m, off + dstoptlen);
		*mp = m;
		if (m == NULL)
			return;
	}
	nip6 = (struct ip6_hdr *)(mtod(m, caddr_t) + nioff);
	eh = (struct ip6_ext *)(mtod(m, caddr_t) + off);
	dstoptlen -= sizeof(struct ip6_ext);
	optp = (uint8_t *)(eh + 1);
	while (dstoptlen > 0) {
		if (*optp == IP6OPT_PAD1) {
			optp += 1;
			dstoptlen -= 1;
			continue;
		}
		optlen = *(optp + 1) + sizeof(struct ip6_opt);
		if (optlen > dstoptlen)
			return;
		if (*optp == IP6OPT_ILNP_NONCE) {
			/* Bad offset: */
			if ((caddr_t)optp - mtod(m, caddr_t) != eoff + nioff)
				return;
			ILCC_LOCK(&V_ilcc);
			np = foreignnid_lookup(&V_ilcc,
			    ILNP6_IPV6_TO_NID(&nip6->ip6_dst),
			    ILNP6_IPV6_TO_L64(&nip6->ip6_dst),
			    ILNP6_IPV6_TO_NID(&nip6->ip6_src));
			if (np != NULL) {
				np->n_flags |= ILNP6_FOREIGN_ERROR;
				np->l64_idx = 0;
			}
			ILCC_UNLOCK(&V_ilcc);
			m_freem(m);
			*mp = NULL;
			return;
		}
		optp += optlen;
		dstoptlen -= optlen;
	}
}

/*
 * ILNP locator update input handling.
 */
int
ilnp6_lu_input(struct mbuf *m, int off, int icmp6len)
{
	struct ip6_hdr *ip6;
	struct ilnp_locator_update *lu_hdr;

	ip6 = mtod(m, struct ip6_hdr *);
	lu_hdr = (struct ilnp_locator_update *)((caddr_t)ip6 + off);
	if ((lu_hdr->ilnp_lu_numl64s == 0) ||
	    (icmp6len < sizeof(struct ilnp_locator_update) +
	    (lu_hdr->ilnp_lu_numl64s * sizeof(struct ilnp_lu_l64)))) {
		return (0);
	}

	switch (lu_hdr->ilnp_lu_operation) {
	case LU_OP_ADVERT:
		return lu_input_advert(m, off);
	case LU_OP_ACK:
		lu_input_ack(m, off);
		return (0);
	default:
		return (0);
	}
	/* UNREACHABLE. */
	return (0);
}

/*
 * ILNP locator update advertisement input. Return whether to send an ack.
 */
static int
lu_input_advert(struct mbuf *m, int off)
{
	struct m_tag *mtag;
	struct ilnp_nonce_opt *nonce;
	struct ip6_hdr *ip6;
	struct ilnp_locator_update *lu;
	struct ilnp_lu_l64 *l64, *l64p;
	struct foreignnid *np;
	struct foreignl64 *lp, *tmp;
	size_t size;
	uint8_t count;

	/* Decode locator update advertisement. */
	mtag = m_tag_find(m, PACKET_TAG_IPOPTIONS, NULL);
	if (mtag == NULL)
		return (0);
	nonce = (struct ilnp_nonce_opt *)(mtag + 1);
	ip6 = mtod(m, struct ip6_hdr *);

	lu = (struct ilnp_locator_update *)((caddr_t)ip6 + off);
	size = lu->ilnp_lu_numl64s * sizeof(struct ilnp_lu_l64);
	l64 = malloc(size, M_ILNP6, M_NOWAIT);
	if (l64 == NULL)
		return (0);
	m_copydata(m, off + sizeof(*lu), size, (caddr_t)l64);

	ILCC_LOCK(&V_ilcc);
	
	/* (Implicit nonce authentication via lookup) */
	np = foreignnid_lookup_nonce(&V_ilcc, ILNP6_IPV6_TO_NID(&ip6->ip6_src), nonce);
	if (np == NULL) {
		ILCC_UNLOCK(&V_ilcc);
		free(l64, M_ILNP6);
		return (0);
	}

	/* Discard all L64s and rebuild the list. */
	LIST_FOREACH_SAFE(lp, &np->n_l64list, l_list, tmp)
		foreignl64_delete(lp);

	/* Add new L64s. */
	l64p = l64;
	for (count = lu->ilnp_lu_numl64s; count > 0; --count, l64p++) {
		foreignl64_update(np, (struct ilnp6_l64 *) &l64p->locator,
		    ntohs(l64p->preference), ntohs(l64p->lifetime) + time_uptime);
	}
	np->l64_idx = 0;
	ILCC_UNLOCK(&V_ilcc);
	free(l64, M_ILNP6);

	/* Send an acknowledgement. */
	return (1);
}

/*
 * ILNP locator update acknowledgment input.
 */
static int
lu_input_ack(struct mbuf *m, int off)
{
	struct m_tag *mtag;
	struct ilnp_nonce_opt *nonce;
	struct ip6_hdr *ip6;
	struct foreignnid *np;

	/* Ignore if missing nonce. */
	mtag = m_tag_find(m, PACKET_TAG_IPOPTIONS, NULL);
	if (mtag == NULL)
		return (0);
	nonce = (struct ilnp_nonce_opt *)(mtag + 1);
	ip6 = mtod(m, struct ip6_hdr *);

	/* Stop retransmissions. */
	ILCC_LOCK(&V_ilcc);
	np = foreignnid_lookup_nonce(&V_ilcc, ILNP6_IPV6_TO_NID(&ip6->ip6_src), nonce);
	if (np != NULL) {
		np->n_flags &= ~ILNP6_FOREIGN_LUPENDING;
		callout_stop(&np->n_lucallout);
	}
	ILCC_UNLOCK(&V_ilcc);
	return (0);
}

/*
 * Check if an IPv6 input packet is ILNP6 by checking for a nonce.
 */
int
is_mbuf_ilnp6(struct mbuf *m)
{
	if (V_ilnp6_enable && (m_tag_find(m, PACKET_TAG_IPOPTIONS, NULL) != NULL))
		return (1);
	return (0);
}

/*
 * Check if an IPv6 destination address is ILNP6.
 */
int
is_dst_ilnp6(struct ilcc *ilp, struct in6_addr *src, struct in6_addr *dst)
{
	struct foreignnid *np;
	int ilnp = 0;

	ILCC_LOCK(ilp);
	np = foreignnid_lookup(ilp, ILNP6_IPV6_TO_NID(dst), ILNP6_IPV6_TO_L64(dst),
	    ILNP6_IPV6_TO_NID(src));
	if (np != NULL)
		ilnp = ((np->n_flags & ILNP6_FOREIGN_ERROR) == 0)? 0: 1;
	ILCC_UNLOCK(ilp);
	return (ilnp);
}

/*
 * Get the length of the nonce destination option.
 */
int
ilnp6_nonce_optlen(struct ilcc *ilp, struct inpcb *inp)
{
	struct foreignnid *np;
	int len = 0;

	if (V_ilnp6_enable && (np = foreignnid_lookup_inpcb(inp)) != NULL) {
		ILCC_LOCK(ilp);
		len = ILNP6_NONCE_DESTLEN(&np->n_lnonce);
		ILCC_UNLOCK(ilp);
	}
	return (len);
}

/*
 * Update TCP response when required.
 * Assume that the IPv6 is in order or not provided, i.e. tcp_respond()
 * was not called from tcp_input() with a mbuf.
 *
 * EADDRNOTAVAIL for local I-LV problems
 * EHOSTUNREACH for foreign I-LV problems
 *
 * Update INP based on ILCC changes:
 * 	* If remote has changed:
 * 		* Assume NID is valid (ie, IPv6-like behavior)
 * 		* Change L64 if needed
 * 	* If local has changed:
 * 		* Check NID is valid
 * 	* If remote L64 or local entry has changed:
 * 		* Update route
 *
 */
int
ilnp6_update_inpcb(struct ilcc *ilp, struct inpcb *inp, struct ip6_hdr *ip6)
{
	struct foreignl64 *nlp;
	struct foreignnid *np;
	struct ilnp6_ilv *lilv, *filv;
	struct locall64 *llp;

	INP_WLOCK_ASSERT(inp);
	
	if (!V_ilnp6_enable)
		return (0);

	if ((np = foreignnid_lookup_inpcb(inp)) == NULL)
		return (0);

	lilv = (struct ilnp6_ilv *)&inp->in6p_laddr;
	filv = (struct ilnp6_ilv *)&inp->in6p_faddr;

	ILCC_LOCK(ilp);
	/* Check if remote node updates need applied. */
	
	/* Check remote still supports ILNP. */
	if ((np->n_flags & ILNP6_FOREIGN_ERROR) != 0) {
		foreignnid_delete(ilp, np);
		inp->inp_flags2 &= ~INP_ILNP6_CONNECTED;
		ILCC_UNLOCK(ilp);
		return (EAGAIN);
	}

	/* Change foreign l64. The previous value may be invalid,
		and we want to spread packets either way. */
	if ((nlp = LIST_FIRST(&np->n_l64list)) == NULL) {
		// No remote L64s -- unreachable
		ILCC_UNLOCK(ilp);
		return (EHOSTUNREACH);
	}
	for (int i = 0; i<np->l64_idx; i++) {
		nlp = LIST_NEXT(nlp, l_list);
	}
	if (LIST_NEXT(nlp, l_list) == NULL) {
		np->l64_idx = 0;
	} else {
		np->l64_idx++;
	}
	ILNP6_L64_COPY(&nlp->l_l64, &filv->ilv_l64);

	/* Spread packets over all local L64s for redundancy. */
	if ((llp = locall64_select_best(ilp, 1)) == NULL) {
		ILCC_UNLOCK(ilp);
		return (EADDRNOTAVAIL);
	}
	ILNP6_L64_COPY(&llp->ll_l64, &lilv->ilv_l64);

	/* Rest of struct is pre-set. */
	bcopy(&llp->ll_gw, &inp->ilnp6_gw.sin6_addr, sizeof(struct in6_addr));

	/* Update existing fields. */
	if (ip6 != NULL) {
		bcopy(&inp->in6p_faddr, &ip6->ip6_dst, sizeof(struct in6_addr));
		bcopy(&inp->in6p_laddr, &ip6->ip6_src, sizeof(struct in6_addr));
	}
	ILCC_UNLOCK(ilp);
	return (0);
}

/*
 * Add the nonce option to an outgoing mbuf. Used for ICMP reflect.
 */
int
ilnp6_nonce_output_mbuf(struct ilcc *ilp, struct ilnp_nonce_dest *dstopt,
    struct mbuf *m)
{
	struct ilnp_nonce_opt *nonce;
	struct m_tag *mtag;

	if (!V_ilnp6_enable)
		return (EOPNOTSUPP);

	/* Check the inbound message had a nonce. */
	mtag = m_tag_find(m, PACKET_TAG_IPOPTIONS, NULL);
	if (mtag == NULL)
		return (EOPNOTSUPP);

	/* TODO: should check we are looking at the right header. */
	nonce = (struct ilnp_nonce_opt *)(mtag + 1);

	/* Add nonce. */
	bcopy(nonce, &dstopt->idn_opt, sizeof(struct ilnp_nonce_opt));
	dstopt->idn_dest.ip6d_nxt = 0;
	/* TODO: should copy this from mbuf, as it may be non-0 */
	dstopt->idn_dest.ip6d_len = 0;
	
	m_tag_delete(m, mtag);
	return (0);
}

/*
 * Add or set the nonce options for outgoing packets. If dst is not NULL,
 * it is used and inp is ignored, else inp is used and dst is ignored.
 */
int
ilnp6_nonce_output(struct ilcc *ilp, struct ilnp_nonce_dest *dstopt,
    struct inpcb *inp)
{
	struct foreignnid *np;
	size_t len;

	if (!V_ilnp6_enable || (np = foreignnid_lookup_inpcb(inp)) == NULL)
		return (EOPNOTSUPP);

	/* Add nonce. */
	ILCC_LOCK(ilp);
	len = ILNP6_NONCE_DESTLEN(&np->n_lnonce);
	bzero(dstopt, sizeof(struct ilnp_nonce_dest));
	ILNP6_NONCE_COPY(&np->n_lnonce, &dstopt->idn_opt);
	dstopt->idn_dest.ip6d_nxt = 0;
	dstopt->idn_dest.ip6d_len = (len >> 3) - 1;

	ILCC_UNLOCK(ilp);
	return (0);
}

/*
 * Set the nonce based on the a foreignnid.
 */
int
ilnp6_nonce_output_np(struct ilcc *ilp, struct ilnp_nonce_dest *dstopt, struct foreignnid *np)
{
	int len;

	if (!V_ilnp6_enable || np == NULL)
		return (EOPNOTSUPP);

	ILCC_LOCK(ilp);
	bzero(dstopt, sizeof(struct ilnp_nonce_dest));
	len = ILNP6_NONCE_DESTLEN(&np->n_lnonce);
	ILNP6_NONCE_COPY(&np->n_lnonce, &dstopt->idn_opt);

	ILCC_UNLOCK(ilp);
	dstopt->idn_dest.ip6d_nxt = 0;
	dstopt->idn_dest.ip6d_len = (len >> 3) - 1;

	return (0);
}

/*
 * Connect a generic node pointer to a node.
 */
int
ilnp6_npconnect(struct ilcc *ilp, struct foreignnid **npp,
    struct in6_addr *laddr, struct in6_addr *faddr)
{
	struct foreignnid *np = NULL;
	int err;

	if (!V_ilnp6_enable)
		return (0);

	ILCC_LOCK(ilp);

	err = foreignnid_update(ilp, &np, ILNP6_IPV6_TO_NID(faddr),
	    ILNP6_IPV6_TO_L64(faddr), ILNP6_IPV6_TO_NID(laddr));

	if (err == 0) {
		*npp = np;
		np->n_refcount++;
	}

	ILCC_UNLOCK(ilp);
	return (err);
}


/*
 * PCB is being connected.
 * INP_WLOCK is held.
 */
int
ilnp6_pcbconnect(struct ilcc *ilp, struct inpcb *inp,
    struct in6_addr *laddr, struct in6_addr *faddr, int *lookupflags)
{
	struct foreignnid *np = NULL;
	int err;
	struct localnid *lnp;
	struct locall64 *llp = NULL;

	INP_WLOCK_ASSERT(inp);

	if (inp->inp_flags2 & INP_ILNP6_CONNECTED)
		return (0);

	if (!V_ilnp6_enable)
		return (EADDRNOTAVAIL);

	/* Cannot use ILNP for non-global unicast destinations. */
	if (!IN6_IS_ADDR_UNSPECIFIED(faddr) &&
	    !ILNP6_IS_ILV_GLOBAL_UNICAST(ILNP6_IPV6_TO_ILV(faddr)))
		return (EINVAL);

	ILCC_LOCK(ilp);

	/*
	 * Unspecified laddr means we must choose a NID for
	 * an outbound connection.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(laddr)) {
		if (ilp->cc_nidpool) {
			/* Use ephemeral NIDs. (Marked as aged by
			 * foreignnid_update)
			 */
			LIST_FOREACH(lnp, &ilp->cc_lnidlist, ln_list) {
				if (lnp->ln_pref <= ILNP6_MAXVALID_PREF &&
				    ((lnp->ln_flags & ILNP6_LOCAL_ACTIVE) == 0) &&
				    ((lnp->ln_flags & ILNP6_LOCAL_AGED) == 0) &&
				    (lnp->ln_flags & ILNP6_LOCAL_EPHEMERAL)) {
					break;
				}
			}
			/* Fail if unable to asign ephemeral NID. */
			if (lnp == NULL) {
				ILCC_UNLOCK(ilp);
				return (EADDRNOTAVAIL);
			}
		}
		else {
			lnp = LIST_FIRST(&ilp->cc_lnidlist);
			if (lnp == NULL || lnp->ln_pref > ILNP6_MAXVALID_PREF
			    || (lnp->ln_flags & ILNP6_LOCAL_AGED)) {
				ILCC_UNLOCK(ilp);
				return (EADDRNOTAVAIL);
			}
		}

		/* Add an l64 to satisfy checks in rest of stack. */
		if ((llp = locall64_select(ilp, NULL)) == NULL) {
			ILCC_UNLOCK(ilp);
			return (EADDRNOTAVAIL);
		}

		ILNP6_NID_COPY(&lnp->ln_nid, &(((struct ilnp6_ilv *)laddr)->ilv_nid));
		ILNP6_L64_COPY(&llp->ll_l64, &(((struct ilnp6_ilv *)laddr)->ilv_l64));
	}

	err = foreignnid_update(ilp, &np, ILNP6_IPV6_TO_NID(faddr),
	    ILNP6_IPV6_TO_L64(faddr),
	    ILNP6_IPV6_TO_NID(laddr));

	if (err == 0) {
		/* Set up the INP. */
		if (lookupflags != NULL)
			*lookupflags = INPLOOKUP_ILNP6;

		np->n_refcount++;
		inp->inp_np = np;
		inp->inp_flags2 |= INP_ILNP6_CONNECTED;
		ip6_setpktopts_ilnp_nonce(inp);
		inp->ilnp6_gw.sin6_family = AF_INET6;
		inp->ilnp6_gw.sin6_len = sizeof(struct sockaddr_in6);
		if (laddr)
			bcopy(laddr, &inp->ilnp6_gw.sin6_addr, sizeof(struct in6_addr));
		else
			bcopy(&llp->ll_gw, &inp->ilnp6_gw.sin6_addr, sizeof(struct in6_addr));
	}

	ILCC_UNLOCK(ilp);
	return (err);
}

/*
 * Disconnect a generic node pointer from the node.
 */
int
ilnp6_npdisconnect(struct ilcc *ilp, struct foreignnid **np)
{
	if (!V_ilnp6_enable || *np == NULL)
		return (0);
	
	ILCC_LOCK(ilp);
	foreignnid_delete(ilp, *np);
	ILCC_UNLOCK(ilp);
	*np = NULL;

	return (0);
}

/*
 * PCB will be disconnected.
 */
int
ilnp6_pcbdisconnect(struct ilcc *ilp, struct inpcb *inp)
{
	struct foreignnid *np;

	if (!V_ilnp6_enable || (inp == NULL))
		return (0);

	INP_WLOCK_ASSERT(inp);

	// TODO: remove ephemeral NIDs only if at least something was sent
	// I can do this by expiring it once something is sent (or recieved)
	// Disconnecting without using it should return it to the pool

	if ((np = foreignnid_lookup_inpcb(inp)) != NULL) {
		ILCC_LOCK(ilp);
		foreignnid_delete(ilp, np);
		ILCC_UNLOCK(ilp);
		inp->inp_flags2 &= ~INP_ILNP6_CONNECTED;
	}

	return (0);
}

/*
 * Select a local I-LV to use. If the INP is given and includes an
 * faddr, try to use an existing NID.
 *
 * Currently, it just selects the prefered local L64, but it should
 * be expanded to make routing decisions.
 */
int
ilnp6_selectsrc(struct ilnp6_ilv *srcp, struct ilcc *ilp, struct inpcb *inp,
    const struct in6_addr *dst, struct ifnet *ifp)
{
	const struct ilnp6_ilv *ilv = ILNP6_IPV6_TO_ILV(dst);

	if (!V_ilnp6_enable)
		return (EAGAIN);

	if (!ILNP6_IS_ILV_GLOBAL_UNICAST(ilv))
		return (EAGAIN);

	/* Must handle cases without an INP to support ping/ICMP reflect. */
	if (inp && !IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr))
		return (selectsrc_inp(srcp, ilp, inp, ilv, ifp));
	else
		return (selectsrc_addr(srcp, ilp, ilv, ifp));
}

/*
 * Select source I-LV based on the inp. &inp->in6p_faddr should
 * not be null.
 */
static int
selectsrc_inp(struct ilnp6_ilv *srcp, struct ilcc *ilp, struct inpcb *inp,
    const struct ilnp6_ilv *dst, struct ifnet *ifp)
{
	struct foreignnid *np;
	struct locall64 *llp;

	INP_WLOCK_ASSERT(inp);

	/* Check INP is ILNP. */
	if ((np = foreignnid_lookup_inpcb(inp)) == NULL)
		return (EAGAIN);

	ILCC_LOCK(ilp);

	/* Check NID is a valid entry. */
	if (localnid_lookup(ilp, &np->n_lnid) == NULL) {
		ILCC_UNLOCK(ilp);
		return (EADDRNOTAVAIL);
	}

	if ((llp = locall64_select(ilp, ifp)) == NULL) {
		ILCC_UNLOCK(ilp);
		return (EADDRNOTAVAIL);
	}
	ILNP6_NID_COPY(&np->n_lnid, &srcp->ilv_nid);
	ILNP6_L64_COPY(&llp->ll_l64, &srcp->ilv_l64);
	ILCC_UNLOCK(ilp);
	return (0);
}

/*
 * Source address selection using the address.
 */
static int
selectsrc_addr(struct ilnp6_ilv *srcp, struct ilcc *ilp,
    const struct ilnp6_ilv *dst, struct ifnet *ifp)
{
	struct localnid *lnp;
	struct locall64 *llp;

	ILCC_LOCK(ilp);
	
	lnp = LIST_FIRST(&ilp->cc_lnidlist);
	if (lnp == NULL || lnp->ln_pref > ILNP6_MAXVALID_PREF) {
		ILCC_UNLOCK(ilp);
		return (EAGAIN);
	}
	
	llp = locall64_select(ilp, ifp);
	if (llp == NULL) {
		ILCC_UNLOCK(ilp);
		return (EAGAIN);
	}
	// TODO: mark NID as in use, and set pref to invalid so it is not chosen in future
	// reference it here? Otherwise we have a race.
	ILNP6_NID_COPY(&lnp->ln_nid, &srcp->ilv_nid);
	ILNP6_L64_COPY(&llp->ll_l64, &srcp->ilv_l64);
	ILCC_UNLOCK(ilp);
	return (0);
}

/*
 * Get the first valid L64.
 */
static struct locall64 *
locall64_select(struct ilcc *ilp, struct ifnet *ifp)
{
	struct locall64 *lp;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	LIST_FOREACH(lp, &ilp->cc_ll64list, ll_list) {
		if ((lp->ll_flags & ILNP6_LOCAL_EXPIRED) == 0) {
			return (lp);
		}
	}
	return (NULL);
}

/*
 * Select a local L64 to use based on a score.
 */
static struct locall64 *
locall64_select_best(struct ilcc *ilp, int32_t weight)
{
	struct locall64 *llp, *lp;
	lp = locall64_select(ilp, NULL);
	if (lp == NULL)
		return (NULL);
	
	/* Find usable L64 with lowest ll_score. */
	LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
		if ((llp->ll_flags & ILNP6_LOCAL_EXPIRED) == 0 &&
				llp->ll_score < lp->ll_score) {
			lp = llp;
		}
	}
	
	LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
		llp->ll_score -= weight;
		lp->ll_score += weight;
	}

	return (lp);
}

/*
 * Handle ILNP6 ioctls.
 */
int
ilnp6_ioctl(unsigned long cmd, caddr_t data)
{
	int error = 0;

	if (!V_ilnp6_enable)
		return (EPFNOSUPPORT);

	switch (cmd) {
	case SIOCSLOCAL_ILNP6: {
		/* Set a local entry. */
		struct ilnp6_lreq *req = (struct ilnp6_lreq *)data;

		/* preference is invalid or under max. */
		if ((req->lr_pref != ILNP6_INVALID_PREF) &&
		    (req->lr_pref > ILNP6_MAXVALID_PREF))
			return (EINVAL);

		/* Zero L64 means this is a NID (else, it is L64). */
		if (ILNP6_IS_L64_ZERO(&req->lr_l64)) {
			/* Both 0 is invalid. */
			if (ILNP6_IS_NID_ZERO(&req->lr_nid))
				return (EINVAL);

			error = localnid_update(&V_ilcc, &req->lr_nid, req->lr_pref, req->lr_flags);
			break;
		}
		else {
			/* Both non-zero is invalid. */
			if (!ILNP6_IS_NID_ZERO(&req->lr_nid))
				return (EINVAL);

			/* Only global unicast. */
			if (!ILNP6_IS_ILV_GLOBAL_UNICAST(&req->lr_ilv))
				return (EINVAL);

			/* Manually setting an L64 is invalid (use NDP) */
			return (EINVAL);
		}
		/* I_L vector - ignore. */
		break;
	    }

	case SIOCGLOCAL_ILNP6: {
		/* Get a local entry. */
		struct ilnp6_lreq *req = (struct ilnp6_lreq *)data;
		struct localnid *lnp;
		struct locall64 *llp;

		/* If zero L64, use NID, else treat as L64. */
		if (ILNP6_IS_L64_ZERO(&req->lr_ilv.ilv_l64)) {
			/* Both 0 is invalid. */
			if (ILNP6_IS_NID_ZERO(&req->lr_nid))
				return (EINVAL);

			ILCC_LOCK(&V_ilcc);
			lnp = localnid_lookup(&V_ilcc,
			    &req->lr_ilv.ilv_nid);
			if (lnp == NULL) {
				ILCC_UNLOCK(&V_ilcc);
				return (ENOENT);
			}
			req->lr_pref = lnp->ln_pref;
			req->lr_flags = lnp->ln_flags;
			req->lr_refs = lnp->ln_refs;

			ILCC_UNLOCK(&V_ilcc);
			break;
		}
		else {
			/* Both non-zero is invalid. */
			if (!ILNP6_IS_NID_ZERO(&req->lr_nid))
				return (EINVAL);

			ILCC_LOCK(&V_ilcc);
			llp = locall64_lookup(&V_ilcc, &req->lr_l64);
			if (llp == NULL) {
				ILCC_UNLOCK(&V_ilcc);
				return (ENOENT);
			}
			else {
				req->lr_pref = llp->ll_pref;
				bcopy(&llp->ll_gw, &req->lr_gw, sizeof(struct in6_addr));

				if (llp->ll_expire == 0)
				        req->lr_expire = 0;
				else {
					if (llp->ll_expire > llp->ll_recv)
						req->lr_expire = llp->ll_expire;
					else
						req->lr_expire = llp->ll_recv;
				}

				req->lr_flags = llp->ll_flags;
				req->lr_if = llp->ll_if;
			}
			ILCC_UNLOCK(&V_ilcc);
			break;
		}

		/* I_L vector - ignore. */
		break;
	    }

	case SIOCFLOCAL_ILNP6: {
		/* Delete a local entry. */
		struct ilnp6_lreq *req = (struct ilnp6_lreq *)data;

		/* zero locator means NID. */
		if (ILNP6_IS_L64_ZERO(&req->lr_ilv.ilv_l64)) {
			struct localnid *lnp;
			/* Both zero is invalid. */
			if (ILNP6_IS_NID_ZERO(&req->lr_nid))
				return (EINVAL);
			ILCC_LOCK(&V_ilcc);
			if ((lnp = localnid_lookup(&V_ilcc, &req->lr_nid)) != NULL)
				error = localnid_age(&V_ilcc, lnp);
			ILCC_UNLOCK(&V_ilcc);
			break;
		}
		else {
			struct locall64 *llp;
			/* Both non-zero is invalid. */
			if (!ILNP6_IS_NID_ZERO(&req->lr_nid))
				return (EINVAL);
			ILCC_LOCK(&V_ilcc);
			if ((llp = locall64_lookup(&V_ilcc, &req->lr_l64)) != NULL)
				error = locall64_delete(&V_ilcc, llp);
			ILCC_UNLOCK(&V_ilcc);
			break;
		}

		/* I_L vector - ignore. */
		break;
	    }

	case SIOCSNODE_ILNP6: {
		/* Create foreign node. */
		struct ilnp6_nreq *req = (struct ilnp6_nreq *)data;

		/* sanity checks on the i_l vector */
		if (!ILNP6_IS_ILV_GLOBAL_UNICAST(&req->nr_ilv) ||
		    ILNP6_IS_ILV_ZERO(&req->nr_ilv))
			return (EADDRNOTAVAIL);

		/* preference is invalid or 16 bits. */
		if ((req->nr_l64pref != ILNP6_INVALID_PREF) &&
		     (req->nr_l64pref > ILNP6_MAXVALID_PREF))
			return (EINVAL);

		ILCC_LOCK(&V_ilcc);

		error = addrinfo_update(&V_ilcc, &req->nr_ilv,
		    time_uptime + req->nr_nidexpire, time_uptime + req->nr_l64expire, req->nr_l64pref);
		ILCC_UNLOCK(&V_ilcc);
		break;
	    }

	case SIOCGNODE_ILNP6: {
		/* Get foreign node. */
		struct ilnp6_nreq *req = (struct ilnp6_nreq *)data;
		struct foreignl64 *lp, *lptmp;
		struct foreignnid *np;
		int addrinfo = 0;
		size_t l64count;

		ILCC_LOCK(&V_ilcc);

		if (ILNP6_IS_NID_ZERO(&req->nr_snid)) {
			addrinfo = 1;
		}

		LIST_FOREACH(np, ILNP6NID_HASH_BUCKET(&V_ilcc, &req->nr_nid), n_nidhash) {
			if (addrinfo == 1) {
				if (((np->n_flags & ILNP6_FOREIGN_ADDRINFO) != 0) &&
				    (ILNP6_ARE_NID_EQUAL(&req->nr_nid, &np->n_nid)))
					break;
			}
			/* Connection, not addrinfo. */
			else if (((np->n_flags & ILNP6_FOREIGN_ADDRINFO) == 0) &&
			    (ILNP6_ARE_NID_EQUAL(&req->nr_nid, &np->n_nid)) &&
			    (foreignl64_lookup(np, &req->nr_l64) != NULL) &&
			    (ILNP6_ARE_NID_EQUAL(&req->nr_snid, &np->n_lnid))) {
					break;
			}
		}

		if (np == NULL) {
			ILCC_UNLOCK(&V_ilcc);
			break;
		}

		req->nr_nidexpire = np->n_expire;

		/* Get the requested l64. */
		lp = LIST_FIRST(&np->n_l64list);
		for (l64count = 0; l64count < req->nr_l64index; l64count++) {
			lp = LIST_NEXT(lp, l_list);
		}
		lptmp = lp;
		while (lptmp != NULL) {
			lptmp = LIST_NEXT(lptmp, l_list);
			l64count++;
		}

		/* Handle user asking for out of bounds l64. */
		if (lp != NULL) {
			req->nr_l64pref = lp->l_pref;
			req->nr_l64expire = lp->l_expire;
			req->nr_ilv.ilv_l64 = lp->l_l64;
		}
		req->nr_l64count = l64count;

		req->nr_refcount = np->n_refcount;
		req->nr_flags = np->n_flags;

		/* if (addrinfo == 0) { */
		ILNP6_NONCE_COPY(&np->n_rnonce, &req->nr_rnonce);
		ILNP6_NONCE_COPY(&np->n_lnonce, &req->nr_lnonce);
		/* } */


		/* XXX: unused. */
		req->nr_nidlastsent = 0;
		req->nr_nidlastrcvd = 0;
		req->nr_l64lastsent = 0;
		req->nr_l64lastrcvd = 0;

		ILCC_UNLOCK(&V_ilcc);
		break;
	    }

	case SIOCFNODE_ILNP6: {
		/* Delete foreign node (addrinfo only, as conns use refcounts). */
		struct ilnp6_nreq *req = (struct ilnp6_nreq *)data;
		struct foreignnid *np;

		/* Only safety check is that it is addrinfo, not an ongoing connection. */
		ILCC_LOCK(&V_ilcc);
		np = addrinfo_lookup(&V_ilcc, &req->nr_nid, &req->nr_l64);
		if (np != NULL)
			foreignnid_destroy(&V_ilcc, np);
		ILCC_UNLOCK(&V_ilcc);
		break;
	    }
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

/*
 * Schedule the sending of LUs. Called with lock held.
 */
static int
lu_output_schedule(struct ilcc *ilp)
{
	struct locall64 *llp;
	struct ilnp_lu_l64 *lp;
	struct foreignnid *np;
	size_t count = 0;

#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	/* TODO
	 * LU ack handling assumes only one LU is in flight at a
	 * time. If therre is existing LU state, we should queue
	 * the new message to be sent once the ACK is recieved.
	 */
	/* Remove old LU state. */
	if (ilp->cc_lul64s != NULL)
		free(ilp->cc_lul64s, M_ILNP6);
	ilp->cc_lul64s = NULL;

	/* Store new LU state in ILCC. */
	LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
		if ((llp->ll_flags & ILNP6_LOCAL_EXPIRED) == 0 &&
			llp->ll_pref <= ILNP6_MAXVALID_PREF)
			count++;
	}

	if (count == 0)
		return (0);
	if (count > UINT8_MAX)
		count = UINT8_MAX;
	
	ilp->cc_lul64s = malloc(count * sizeof(struct ilnp_lu_l64),
	    M_ILNP6, M_NOWAIT);

	if (ilp->cc_lul64s == NULL)
		return (ENOMEM);

	ilp->cc_lul64count = count;
	lp = ilp->cc_lul64s;
	LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
		if ((llp->ll_flags & ILNP6_LOCAL_EXPIRED) == 0 &&
			llp->ll_pref <= ILNP6_MAXVALID_PREF) {
			bcopy(&llp->ll_l64, &lp->locator, sizeof(uint64_t));
			lp->preference = htons((uint16_t)llp->ll_pref);
			lp->lifetime = htons((uint16_t)V_ilnp6_lu_ttl);
			lp++;
		}
	}

	/* Find active remote nodes needing LUs and schedule sending. */
	LIST_FOREACH(np, &ilp->cc_fnidlist, n_list) {
		if (ILNP6_IS_NID_ZERO(&np->n_lnid))
			continue;
		np->n_flags |= ILNP6_FOREIGN_LUPENDING;
		np->n_luretrans = 0;
		callout_reset(&np->n_lucallout, 
		    (arc4random() % (V_ilnp6_lu_max_delay * hz / 10)),
		    lu_output, np);
	}
	return (0);
}

/*
 * Send a locator update.
 */
static void
lu_output(void *arg)
{
	struct foreignnid *np = (struct foreignnid *)arg;
	struct ilcc *ilp = np->n_ilcc;
	struct epoch_tracker et;
	struct foreignl64 *nlp;
	struct locall64 *llp;
	struct ifnet *ifp;
	struct ilnp6_ilv ilv_dst;
	struct ilnp6_ilv ilv_src;
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct ilnp_locator_update *lu;
	struct ip6_pktopts opt;
	struct ilnp_nonce_dest dstopt;
	size_t len, extra;


#ifdef INVARIANTS
	ILCC_LOCK_ASSERT(ilp);
#endif
	CURVNET_SET(ilp->cc_vnet);
	NET_EPOCH_ENTER(et);

	if ((np->n_flags & ILNP6_FOREIGN_LUPENDING) == 0)
		goto done;

	/* Stop trying to send updates if we have no l64s. */
	if (ilp->cc_lul64s == NULL)
		goto done;

	/* Schedule retransmission just in case. */
	np->n_luretrans++;
	if (np->n_luretrans < V_ilnp6_lu_max_retrans)
		callout_reset(&np->n_lucallout, np->n_luretrans * hz,
		    lu_output, np);

	/* Set the dstination ILV. */
	if ((nlp = LIST_FIRST(&np->n_l64list)) == NULL)
		goto done;
	ILNP6_L64_COPY(&nlp->l_l64, &ilv_dst.ilv_l64);
	ILNP6_NID_COPY(&np->n_nid, &ilv_dst.ilv_nid);

	/* Set the source ILV. Because we have a nonce, we can use any local L64. */
	ifp = NULL;
	if ((llp = locall64_select(ilp, ifp)) == NULL)
		goto done;
	ILNP6_L64_COPY(&llp->ll_l64, &ilv_src.ilv_l64);
	ILNP6_NID_COPY(&np->n_lnid, &ilv_src.ilv_nid);

	/* Set up mbuf. */
	len = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
	len += ilp->cc_lul64count * sizeof(struct ilnp_lu_l64);
	extra = max_linkhdr + ILNP6_NONCE_DESTLEN(&np->n_lnonce);
	if (len + extra > MCLBYTES) {
		goto done;
	}
	if (len + extra > MHLEN)
		m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	else
		m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL)
		goto done;
	m->m_pkthdr.len = m->m_len = len;
	m_align(m, len);

	/* IP6 Header Info. */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_dst = *(struct in6_addr *)&ilv_dst;
	ip6->ip6_src = *(struct in6_addr *)&ilv_src;
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_hlim = ifp ? ND_IFINFO(ifp)->chlim : V_ip6_defhlim;

	/* LU Contents. */
	lu = (struct ilnp_locator_update *)(ip6 + 1);
	lu->ilnp_lu_type = ILNP6_LOCATOR_UPDATE;
	lu->ilnp_lu_code = 0;
	lu->ilnp_lu_numl64s = ilp->cc_lul64count;
	lu->ilnp_lu_operation = LU_OP_ADVERT;
	lu->ilnp_lu_reserved16 = 0;
	bcopy(ilp->cc_lul64s, lu + 1,
	    ilp->cc_lul64count * sizeof(struct ilnp_lu_l64));
	lu->ilnp_lu_cksum = 0;
	lu->ilnp_lu_cksum = in6_cksum(m, IPPROTO_ICMPV6,
	    sizeof(struct ip6_hdr), len - sizeof(struct ip6_hdr));
	
	/* Add nonce. */
	bzero(&dstopt, sizeof(struct ilnp_nonce_dest));
	len = ILNP6_NONCE_DESTLEN(&np->n_lnonce);
	ILNP6_NONCE_COPY(&np->n_lnonce, &dstopt.idn_opt);
	
	dstopt.idn_dest.ip6d_nxt = 0;
	dstopt.idn_dest.ip6d_len = (len >> 3) - 1;
	ip6_initpktopts(&opt);
	opt.ip6po_dest2 = &dstopt.idn_dest;

	ip6_output(m, &opt, NULL, 0, NULL, &ifp, NULL);
#if 0
	if (ifp)
		icmp6_ifoutstat_inc(ifp, ILNP6_LOCATOR_UPDATE, 0);
#endif

done:
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
}


/*
 * Convert NID or locator to printable (loggable) representation.
 * Caller has to make sure that buf is at least ILNP6_NIDSTRLEN long.
 */
char *
ilnp6_sprintf(char *buf, const struct ilnp6_addr *addr)
{
	const uint8_t *binary = &addr->i6_addr[0];
	int nib;
	int i;
	char *start;

	start = buf;
	for (i = 0; i < 4; i++) {
		nib = *binary >> 4;
		*buf++ = nib + (nib < 10 ? '0' : 'W');
		nib = *binary++ & 0x0f;
		*buf++ = nib + (nib < 10 ? '0' : 'W');

		nib = *binary >> 4;
		*buf++ = nib + (nib < 10 ? '0' : 'W');
		nib = *binary++ & 0x0f;
		*buf++ = nib + (nib < 10 ? '0' : 'W');

		if (i < 3)
			*buf++ = ':';
	}
	*buf = '\0';
	return (start);
}

/*
 * Convert nonce content to printable (loggable) representation.
 * Caller has to make sure that buf is at least ILNP6_NONCESTRLEN long.
 */
char *
ilnp6_nonce_sprintf(char *buf, const struct ilnp_nonce_opt *nonce)
{
	size_t i, plen = ILNP6_NONCE_LEN(nonce);
	char *start;
	int nib;

	/* Len should be 4 or 12. */
	if (plen != 4 && plen != 12) {
		*buf = '\0';
		return (buf);
	}

	start = buf;
	for (i = 0; i < plen; i++) {
		nib = nonce->ion_nonce[i] >> 4;
		*buf++ = nib + (nib < 10 ? '0' : 'W');
		nib = nonce->ion_nonce[i] & 0x0f;
		*buf++ = nib + (nib < 10 ? '0' : 'W');
	}
	*buf = '\0';
	return (start);
}

/*
 * Update the ILVs used by an arbitrary node pointer.
 */
int
ilnp6_update_np(struct ilcc *ilp, struct in6_addr *laddr, struct in6_addr *faddr, struct foreignnid *np)
{
	struct foreignl64 *nlp;
	struct locall64 *llp;
	struct ilnp6_ilv *lilv, *filv;

	if (!V_ilnp6_enable)
		return (0);

	lilv = (struct ilnp6_ilv *)laddr;
	filv = (struct ilnp6_ilv *)faddr;

	ILCC_LOCK(ilp);

	/* Update laddr. */
	if ((llp = locall64_select_best(ilp, 1)) == NULL) {
			ILCC_UNLOCK(ilp);
		return (EADDRNOTAVAIL);
	}
	ILNP6_L64_COPY(&llp->ll_l64, &lilv->ilv_l64);

	/*
	 * Update faddr. We have recieved a SYN, so
	 * know it supports ILNP, but have no cached L64
	 * or route to update.
	 */
	if ((nlp = LIST_FIRST(&np->n_l64list)) == NULL) {
		/* Should never happen. */
		ILCC_UNLOCK(ilp);
		return (EHOSTUNREACH);
	}
	ILNP6_L64_COPY(&nlp->l_l64, &filv->ilv_l64);

	ILCC_UNLOCK(ilp);
	return (0);
}




/*
 * Check if an IPv6 forwarding packet should be treated as ILNP6 by
 * checking for a nonce extension header in the IP6 header, or in
 * the inner IP6 header of an ICMP error message.
 */
int
is_ilnp6_mbuf_fw(struct mbuf **mp, int off)
{
	struct mbuf *m = *mp;
	struct icmp6_hdr *icmp6;
	int proto = 0;
	int offset = off;

	if (is_ilnp6_mbuf_fw_hdr(m, &offset, &proto))
		return (1);

	/*
	 * From nptv6_translate_icmp6.
	 *
	 * If it is an IPv6 error message but the inner message
	 * is ILNP, treat it as ILNP.
	 */
	if (proto == IPPROTO_ICMPV6) {
		icmp6 = mtodo(m, offset);
		switch (icmp6->icmp6_type) {
		case ICMP6_DST_UNREACH:
		case ICMP6_PACKET_TOO_BIG:
		case ICMP6_TIME_EXCEEDED:
		case ICMP6_PARAM_PROB:
			offset += sizeof(*icmp6);
			if (offset + sizeof(struct ip6_hdr *) > m->m_pkthdr.len)
				return (0);
			if (offset + sizeof(struct ip6_hdr *) > m->m_len)
				*mp = m = m_pullup(m, offset +
				    sizeof(struct ip6_hdr *));
			if (m == NULL)
				return (0);
			return (is_ilnp6_mbuf_fw_hdr(m, &offset, &proto));
		default:
			return (0);
		}
	}
	return (0);
}

/*
 * Search an mbuf for a nonce header.
 *
 * Skeleton from nptv6_getlasthdr.
 */
static int
is_ilnp6_mbuf_fw_hdr(struct mbuf *m, int *offset, int *last)
{
	struct ip6_hdr *ip6;
	struct ip6_hbh *hbh;
	struct ip6_opt *opt;
	int proto, hlen;

	hlen  = *offset;
	if (m->m_len < hlen)
		return (0);
	ip6 = mtodo(m, hlen);
	hlen += sizeof(*ip6);
	proto = ip6->ip6_nxt;
	while (proto == IPPROTO_HOPOPTS || proto == IPPROTO_ROUTING ||
	    proto == IPPROTO_DSTOPTS) {
		if (proto == IPPROTO_DSTOPTS) {
			opt = mtodo(m, hlen + 2);
			if (opt->ip6o_type == IP6OPT_ILNP_NONCE)
				return (1);
		}
		hbh = mtodo(m, hlen);
		if (m->m_len < hlen)
			return (0);
		proto = hbh->ip6h_nxt;
		hlen += (hbh->ip6h_len + 1) << 3;
	}
	*last = proto;
	*offset = hlen;
	return (0);
}

/* Add foreign L64 is if it new. */
int
ilnp6_pcbupdate(struct ilcc *ilp, struct inpcb *inp, struct in6_addr *faddr)
{
	struct foreignnid *np = inp->inp_np;

	ILCC_LOCK(ilp);
	if (foreignl64_lookup(np, ILNP6_IPV6_TO_L64(faddr)) == NULL) {
	    foreignl64_update(np, ILNP6_IPV6_TO_L64(faddr),
			V_ilnp6_on_input_pref, time_uptime + V_ilnp6_on_input_ttl);
	}
	ILCC_UNLOCK(ilp);
	return (0);
}

/*
 * Remove L64s from a now invalid interface
 */
int
ilnp6_if_unroute(struct ilcc *ilp, struct ifnet *ifp)
{
	struct locall64 *llp;
	ILCC_LOCK(ilp);
	LIST_FOREACH(llp, &ilp->cc_ll64list, ll_list) {
		if (llp->ll_if == ifp->if_index)
			llp->ll_flags |= ILNP6_LOCAL_EXPIRED;
	}
	/* Send LU ASAP. */
	lu_output_schedule(ilp);
	ILCC_UNLOCK(ilp);
	return (0);
}


/* Adapted from in6_cksum.c */
#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; (void)ADDCARRY(sum);}

union l_util {
	uint16_t	s[2];
	uint32_t	l;
};

union s_util {
	uint8_t		c[2];
	uint16_t	s;
};

static int
in6_cksumdata(void *data, int *lenp, uint8_t *residp, int rlen)
{
	union l_util l_util;
	union s_util s_util;
	uint16_t *w;
	int len, sum;
	bool byte_swapped;

	KASSERT(*lenp >= 0, ("%s: negative len %d", __func__, *lenp));
	KASSERT(rlen == 0 || rlen == 1, ("%s: rlen %d", __func__, rlen));

	len = *lenp;
	sum = 0;

	if (len == 0) {
		len = rlen;
		goto out;
	}

	byte_swapped = false;
	w = data;

	/*
	 * Do we have a residual byte left over from the previous buffer?
	 */
	if (rlen == 1) {
		s_util.c[0] = *residp;
		s_util.c[1] = *(uint8_t *)w;
		sum += s_util.s;
		w = (uint16_t *)((uint8_t *)w + 1);
		len--;
		rlen = 0;
	}

	/*
	 * Force to even boundary.
	 */
	if ((1 & (uintptr_t)w) && len > 0) {
		REDUCE;
		sum <<= 8;
		s_util.c[0] = *(uint8_t *)w;
		w = (uint16_t *)((uint8_t *)w + 1);
		len--;
		byte_swapped = true;
	}

	/*
	 * Unroll the loop to make overhead from branches &c small.
	 */
	while ((len -= 32) >= 0) {
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
		sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
		sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
		sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
		w += 16;
	}
	len += 32;
	while ((len -= 8) >= 0) {
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
		w += 4;
	}
	len += 8;
	if (len == 0 && !byte_swapped)
		goto out;
	REDUCE;
	while ((len -= 2) >= 0) {
		sum += *w++;
	}
	if (byte_swapped) {
		REDUCE;
		sum <<= 8;
		if (len == -1) {
			s_util.c[1] = *(uint8_t *)w;
			sum += s_util.s;
		} else /* len == -2 */
			*residp = s_util.c[0];
		len++;
	} else if (len == -1)
		*residp = *(uint8_t *)w;
out:
	*lenp = len & 1;
	return (sum);
}

struct in6_cksum_partial_arg {
	int	sum;
	int	rlen;
	uint8_t	resid;
};

static int
in6_cksum_partial_one(void *_arg, void *data, u_int len)
{
	struct in6_cksum_partial_arg *arg = _arg;

	arg->sum += in6_cksumdata(data, &len, &arg->resid, arg->rlen);
	arg->rlen = len;
	return (0);
}

/*
 * Specialized version of _in6_cksum_pseudo for ILNP6.
 * No scope, skip locator parts in addresses.
 */
static int
_ilnp6_cksum_pseudo(struct ip6_hdr *ip6, uint32_t len, uint8_t nxt,
    uint16_t csum)
{
	int sum;
	uint16_t *w;
	union {
		u_int16_t phs[4];
		struct {
			u_int32_t	ph_len;
			u_int8_t	ph_zero[3];
			u_int8_t	ph_nxt;
		} __packed ph;
	} uph;

	sum = csum;

	/*
	 * First create IP6 pseudo header and calculate a summary.
	 */
	uph.ph.ph_len = htonl(len);
	uph.ph.ph_zero[0] = uph.ph.ph_zero[1] = uph.ph.ph_zero[2] = 0;
	uph.ph.ph_nxt = nxt;

	/* Payload length and upper layer identifier. */
	sum += uph.phs[0];  sum += uph.phs[1];
	sum += uph.phs[2];  sum += uph.phs[3];

	/* ILNP source NID -- ignore L64 and scope*/
	w = (uint16_t *)&ip6->ip6_src;
	sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];

	/* ILNP dst  NID -- ignore L64 and scope*/
	w = (uint16_t *)&ip6->ip6_dst;
	sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];

	return (sum);
}

int
ilnp6_cksum_pseudo(struct ip6_hdr *ip6, uint32_t len, uint8_t nxt,
    uint16_t csum)
{
	union l_util l_util;
	int sum;

	sum = _ilnp6_cksum_pseudo(ip6, len, nxt, csum);
	REDUCE;
	return (sum);
}

/*
 * Specialized version of in6_cksum_partial for ILNP6.
 * No scope, skip locator parts in addresses.
 */
int
ilnp6_cksum_partial(struct mbuf *m, uint8_t nxt, uint32_t off,
    uint32_t len, uint32_t cov)
{
	struct in6_cksum_partial_arg arg;
	union l_util l_util;
	union s_util s_util;
	struct ip6_hdr *ip6;
	uint16_t *w;
	int sum;
	union {
		uint16_t phs[4];
		struct {
			uint32_t	ph_len;
			uint8_t		ph_zero[3];
			uint8_t		ph_nxt;
		} __packed ph;
	} uph;

	/* Sanity check. */
	KASSERT(m->m_pkthdr.len >= off + len, ("%s: mbuf len (%d) < off(%d)+"
	    "len(%d)", __func__, m->m_pkthdr.len, off, len));
	KASSERT(m->m_len >= sizeof(*ip6),
	    ("%s: mbuf len %d < sizeof(ip6)", __func__, m->m_len));

	/*
	 * First create IP6 pseudo header and calculate a summary.
	 */
	uph.ph.ph_len = htonl(len);
	uph.ph.ph_zero[0] = uph.ph.ph_zero[1] = uph.ph.ph_zero[2] = 0;
	uph.ph.ph_nxt = nxt;

	/* Payload length and upper layer identifier. */
	sum = uph.phs[0];  sum += uph.phs[1];
	sum += uph.phs[2];  sum += uph.phs[3];

	ip6 = mtod(m, struct ip6_hdr *);

	/* ILNP src NID. */
	w = (uint16_t *)&ip6->ip6_src;
	sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];

	/* ILNP src NID. */
	w = (uint16_t *)&ip6->ip6_dst;
	sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];

	/*
	 * Loop over the rest of the mbuf chain and compute the rest of the
	 * checksum.  m_apply() handles unmapped mbufs.
	 */
	arg.sum = sum;
	arg.rlen = 0;
	(void)m_apply(m, off, cov, in6_cksum_partial_one, &arg);
	sum = arg.sum;

	/*
	 * Handle a residual byte.
	 */
	if (arg.rlen == 1) {
		s_util.c[0] = arg.resid;
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;
	return (~sum & 0xffff);
}

int
ilnp6_cksum(struct mbuf *m, uint8_t nxt, uint32_t off, uint32_t len)
{
	return (ilnp6_cksum_partial(m, nxt, off, len, len));
}
