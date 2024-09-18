/*-
  BSD 2-Clause License
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

#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stdint.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <arpa/inet.h> /* XXX Remove */
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ilnp6.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	DEFAULT_PREF	100L

#define HOUR		3600
#define MINUTE		60
#define TIME_STRLEN	256

#define AF_ILV 1
#define AF_NID 2
#define AF_L64 3

// updated functions
static void	 set_nid(char *);
static void	 usage(void);
static void	 delete_nid(char *);
static void	 dump_local_nids(void);
static void	 dump_local_l64s(void);
static void	 print_local_nid(struct ilnp6_lreq *);
static void	 print_local_l64(struct ilnp6_lreq *);
static char	*nonce2str(char *, const struct ilnp_nonce_opt *);
static char	*timeout2str(uint32_t, char *);
static char *ilnp_ntop(int, const void * __restrict, char * __restrict);
static void	 dump_nodes(void);
static void	 print_foreign(struct ilnp6_nreq *);

static int	s = -1;
static char nidbuf[ILNP6_NIDSTRLEN];
static char l64buf[ILNP6_L64STRLEN];
static char ilvbuf[ILNP6_ILVSTRLEN];
	
/*
 * The ilnp tool displays, sets and deletes entries ILNP communication cache.
 */
int
main(int argc, char *argv[])
{
	int ch, mode = 0;
	char *optstr = "ads";

	while ((ch = getopt(argc, argv, optstr)) != -1)
		switch (ch) {
		case 'a':
		case 'd':
		case 's':
			if (mode) {
				if (mode == ch)
					break;
				usage();
				/*NOTREACHED*/
			}
			mode = ch;
			break;
		case '?':
			printf("unknown option '%c'\n", (char)optopt);
		default:
			usage();
			/*NOTREACHED*/
		}
	argc -= optind;
	argv += optind;

	if (argc > 1) {
		usage();
		/*NOTREACHED*/
	}

	switch (mode) {
	case 'a':
		dump_local_nids();
		dump_local_l64s();
		dump_nodes();
		break;
	case 'd':
		/* Delete a local NID. */
		delete_nid(argv[0]);
		break;
	case 's':
		/* Set a local NID. */
		set_nid(argv[0]);
		break;
	default:
		usage();
		/*NOTREACHED*/
		break;
	}
	exit(0);
}

static void
getsocket(void)
{
	if (s < 0) {
		s = socket(PF_INET6, SOCK_DGRAM, 0);
		if (s < 0) {
			err(1, "socket");
			/* NOTREACHED */
		}
	}
}

/*
 * Set a local NID.
 */
static void
set_nid(char *nid)
{
	struct ilnp6_ilv addr;
	struct ilnp6_lreq req;
	char tmp[23];
	char* ptr;
	
	if (strlen(nid) > 21) {
		errx(1, "bad NID %s", nid);
	}
	snprintf(tmp, 23, "::%s", nid);
	ptr = tmp;
	while (*ptr != '\0') {
		if (*ptr == '+')
			*ptr = ':';
		ptr++;
	}
		
	/* parse NID */
	if (inet_pton(AF_INET6, tmp, &addr) != 1) {
		errx(1, "bad NID %s", nid);
		/*NOTREACHED*/
	}

	getsocket();

	/* set NID. */
	bzero(&req, sizeof(req));
	ILNP6_NID_COPY(&addr.ilv_nid, &req.lr_nid);
	req.lr_pref = (uint32_t) 0;
	if (ioctl(s, SIOCSLOCAL_ILNP6, (caddr_t)&req) < 0) {
		err(1, "ioctl(SIOCSLOCAL_ILNP6)");
		/*NOTREACHED*/
	}
}

/*
 * Display a local nid from the ioctl request.
 */
static void
print_local_nid(struct ilnp6_lreq *req)
{
	printf("\t%s\t%d\t\t%d\t\t",
	    ilnp_ntop(AF_NID, &req->lr_nid, nidbuf),
	    req->lr_pref,
	    req->lr_refs);

	/*
	 * Print all flags:
	 *	Valid/Active: Implied by not Aged and refcount: 
	 *	Ephemeral: E
	 *	Aged: X
	 */
	if (req->lr_flags & ILNP6_LOCAL_AGED) {
		printf("X");
	}
	if (req->lr_flags & ILNP6_LOCAL_EPHEMERAL) {
		printf("E");
	}
	printf("\n");
}

/*
 * Display a local locator from the ioctl request.
 */
static void
print_local_l64(struct ilnp6_lreq *req)
{
	char ifname[IFNAMSIZ];
	char gw[40];
	char buf[TIME_STRLEN];
	printf("\t%s\t%d\t%s\t%hhx\t%s\t%s\n",
	    ilnp_ntop(AF_L64, &req->lr_l64, l64buf),
	    req->lr_pref,
	    if_indextoname((unsigned int)req->lr_if, ifname),
	    (unsigned char)req->lr_flags,
	    timeout2str(req->lr_expire, buf),
	    inet_ntop(AF_INET6, &req->lr_gw, gw, 40));
}

/*
 * Display a remote node.
 */
static void
print_foreign(struct ilnp6_nreq *req)
{
	size_t count, lim;
	char buf[TIME_STRLEN];
	char lnonce[ILNP6_NONCESTRLEN];
	char rnonce[ILNP6_NONCESTRLEN];

	printf("Remote Node: %s\n"
	    "\tExpires %s\n"
	    "\tL64\t\t\tPref\tExpires\n",
	    ilnp_ntop(AF_NID, &req->nr_nid, nidbuf),
	    timeout2str(req->nr_nidexpire, buf));
	
	lim = req->nr_l64count;
	for (count = 0; count < lim; count++) {
		req->nr_l64index = count;
		if (ioctl(s, SIOCGNODE_ILNP6, (caddr_t)req) < 0) {
			if (errno == ENOENT) {
				errx(1, "%s: No such remote node",
			    ilnp_ntop(AF_ILV, &req->nr_ilv, ilvbuf));
				/*NOTREACHED*/
			}
			err(1, "ioctl(SIOCGNODE_ILNP6)");
			/*NOTREACHED*/
		}
		/* ILCC may have been updated while we watched. */
		if (req->nr_l64count != lim)
			break;
		printf("\t%s\t%d\t%s\n",
		    ilnp_ntop(AF_L64, &req->nr_l64, l64buf),
		    req->nr_l64pref,
		    timeout2str(req->nr_l64expire, buf));
	}

	printf("\tSource: %s\n"
	    "\tLocal Nonce: %s\n"
	    "\tRemote Nonce: %s\n"
	    "\tRefs: %d\n"
	    "\tFlags: 0x%hhx\n",
	    ilnp_ntop(AF_NID, &req->nr_snid, nidbuf),
	    nonce2str(lnonce, &req->nr_lnonce),
	    nonce2str(rnonce, &req->nr_rnonce),
	    req->nr_refcount,
	    req->nr_flags);
}

/*
 * Delete a local NID.
 */
static void
delete_nid(char *nid)
{
	struct ilnp6_ilv addr;
	struct ilnp6_lreq req;
	char tmp[23];
	char* ptr;
	
	if (strlen(nid) > 21) {
		errx(1, "bad NID %s", nid);
	}
	snprintf(tmp, 23, "::%s", nid);
	ptr = tmp;
	while (*ptr != '\0') {
		if (*ptr == '+')
			*ptr = ':';
		ptr++;
	}
		
	/* parse NID */
	if (inet_pton(AF_INET6, tmp, &addr) != 1) {
		errx(1, "bad NID %s", nid);
		/*NOTREACHED*/
	}

	getsocket();

	/* delete NID. */
	bzero(&req, sizeof(req));
	ILNP6_ILV_COPY(&addr, &req.lr_ilv);
	req.lr_pref = ILNP6_INVALID_PREF;
	if (ioctl(s, SIOCFLOCAL_ILNP6, (caddr_t)&req) < 0) {
		err(1, "ioctl(SIOCFLOCAL_ILNP6)");
		/*NOTREACHED*/
	}
}

/*
 * Dump the local NIDs in the ILCC.
 */
static void
dump_local_nids(void)
{
	char *mib;
	size_t len;
	struct ilnp6_nid *nids, *nid;
	struct ilnp6_lreq req;

	getsocket();

	/* get NIDs. */
	mib = "net.inet6.ilnp6.localnidlist";
	if (sysctlbyname(mib, NULL, &len, NULL, 0) < 0) {
		err(1, "sysctlbyname0");
		/*NOTREACHED*/
	}

	nids = malloc(len);
	if (sysctlbyname(mib, nids, &len, NULL, 0) < 0) {
		err(1, "sysctlbyname");
		/*NOTREACHED*/
	}
	printf("Local\tNID\t\t\tPref\t\tRefs\t\tFlags\n");
	for (nid = nids; len >= sizeof(*nid);
	        nid++, len -= sizeof(*nid)) {
		bzero(&req, sizeof(req));
		ILNP6_NID_COPY(nid, &req.lr_ilv.ilv_nid);
		if (ioctl(s, SIOCGLOCAL_ILNP6, (caddr_t)&req) < 0) {
			if (errno == ENOENT) {
				warnx("%s: No such local nid",
				    ilnp_ntop(AF_NID, &req.lr_nid, nidbuf));
			} else
				warn("ioctl(SIOCGLOCAL_ILNP6)");
		} else
			print_local_nid(&req);
	}
}

/*
 * Dump the local L64s in the ILCC.
 */
static void
dump_local_l64s(void)
{
	char *mib;
	size_t len;
	struct ilnp6_l64 *locs, *loc;
	struct ilnp6_lreq req;

	/* get locators. */
	mib = "net.inet6.ilnp6.locall64list";
	if (sysctlbyname(mib, NULL, &len, NULL, 0) < 0) {
		err(1, "sysctlbyname0");
		/*NOTREACHED*/
	}

	locs = malloc(len);
	if (sysctlbyname(mib, locs, &len, NULL, 0) < 0) {
		err(1, "sysctlbyname");
		/*NOTREACHED*/
	}

	printf("Local\tL64\t\t\tPref\tIface\tValid\tExpires\tGateway\n");
	for (loc = locs; len >= sizeof(*loc);
	    loc++, len -= sizeof(*loc)) {
		bzero(&req, sizeof(req));
		ILNP6_L64_COPY(loc, &req.lr_ilv.ilv_l64);
		if (ioctl(s, SIOCGLOCAL_ILNP6, (caddr_t)&req) < 0) {
			if (errno == ENOENT) {
				warnx("%s: No such local locator",
			    ilnp_ntop(AF_L64, &req.lr_l64, l64buf));
			} else
				warn("ioctl(SIOCGLOCAL_ILNP6)");
		} else
			print_local_l64(&req);
	}
}

/*
 * Dump the remote node part of the ILCC communication cache.
 */
static void
dump_nodes(void)
{
	char *mib;
	size_t len, count, block;
	struct ilnp6_ilv *addr, *nid, *data;
	struct ilnp6_nreq req;

	block = sizeof(*addr) + sizeof(*nid);

	mib = "net.inet6.ilnp6.nodelist";
	if (sysctlbyname(mib, NULL, &len, NULL, 0) < 0) {
		err(1, "sysctlbyname0");
		/*NOTREACHED*/
	}
	count = len;

	data = malloc(count);
	if (sysctlbyname(mib, data, &len, NULL, 0) < 0) {
		err(1, "sysctlbyname");
		/*NOTREACHED*/
	}

	getsocket();
	for (addr = data, nid = addr + 1;
	    len >= block;
	    addr+= 2, nid += 2, len -= block) {
		bzero(&req, sizeof(req));
		ILNP6_ILV_COPY(addr, &req.nr_ilv);
		ILNP6_NID_COPY(&(nid->ilv_nid), &req.nr_snid);
		if (ioctl(s, SIOCGNODE_ILNP6, (caddr_t)&req) < 0) {
			if (errno == ENOENT) {
				warnx("%s: No such remote node",
			    ilnp_ntop(AF_ILV, &req.nr_ilv, ilvbuf));
			} else
				warn("ioctl(SIOCGNODE_ILNP6)");
		} else {
			print_foreign(&req);
		}
	}
	free(data);
}

static void
usage(void)
{
	printf("usage: ilnp -a\n");
	printf("       ilnp -s nid\n");
	printf("       ilnp -d nid\n");
	exit(1);
}

static char *
timeout2str(uint32_t seconds, char *buf)
{
	struct timespec ts;

	if (seconds == 0)
		snprintf(buf, TIME_STRLEN, "Never");
	else {
		clock_gettime(CLOCK_UPTIME, &ts);
		if (ts.tv_sec > seconds) {
			snprintf(buf, TIME_STRLEN, "Expired");
		}
		else {
			seconds = seconds - ts.tv_sec;
			snprintf(buf, TIME_STRLEN, "%d:%02d:%02d",
			    seconds / HOUR, (seconds % HOUR) / MINUTE,
			    seconds % MINUTE);
		}
	}
	return (buf);
}

/*
 * Convert nonce content to printable (loggable) representation.
 * Caller has to make sure that buf is at least ILNP6_NONCESTRLEN long.
 */
static char *
nonce2str(char *buf, const struct ilnp_nonce_opt *nonce)
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
 * Convert an I-LV, NID, or L64 to ASCII. The buffer must be large enough
 * for the string produced for that af.
 * XXX
 * Should eventually be replaced with a more standard call to inet_ntop,
 * however this is not currently defined for ILNP. This is a temporary fix
 * with the same prototype, however af is ignored (it would be something like
 * AF_ILNP).
 */
static char *
ilnp_ntop(int af, const void * __restrict src, char * __restrict dst)
{
	char *cp;
	int i;
	const uint8_t* restrict words;
	cp = dst;

	/* Convert src to array of bytes */
	words = src;

	/* L64 part. */
	if (af == AF_ILV || af == AF_L64) {
		for (i = 0; i < 8; i+= 2) {
			cp += sprintf(cp, "%02x", words[i]);
			cp += sprintf(cp, "%02x", words[i+1]);
			*cp++ = '-';
		}
		words = &words[8];
	}

	if (af == AF_ILV)
		cp[-1] = '.';

	/* NID part. */
	if (af == AF_ILV || af == AF_NID) {
		for (i = 0; i < 8; i+= 2) {
			cp += sprintf(cp, "%02x", words[i]);
			cp += sprintf(cp, "%02x", words[i+1]);
			*cp++ = '+';
		}
	}

	cp[-1] = '\0';
	return (dst);

}
