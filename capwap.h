 /*****************************************************************************
* Linux CAPWAP Sockets
*
* CAPWAP --- Control And Provisioning of Wireless Access Points (RFC-5415, 5416)
*
* Version: 1.0.0
*
* Authors: John Chang (mofish@gmail.com)
*
* License:
*      This program is free software; you can redistribute it and/or
*      modify it under the terms of the GNU General Public License
*      as published by the Free Software Foundation; either version
*      2 of the License, or (at your option) any later version.
*
*/

#ifndef _LINUX_CAPWAP_H_
#define _LINUX_CAPWAP_H_

#include <linux/types.h>
#include <linux/socket.h>
#ifdef __KERNEL__
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

#define IPPROTO_CAPWAP		115

/**
 * struct sockaddr_capwapip - the sockaddr structure for CAPWAP-over-IP sockets
 * @capwap_family:  address family number AF_CAPWAPIP.
 * @capwap_addr:    protocol specific address information
 * @capwap_conn_id: connection id of tunnel
 */
#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/
struct sockaddr_capwapip {
	/* The first fields must match struct sockaddr_in */
	__kernel_sa_family_t capwap_family; /* AF_INET */
	__be16		         capwap_unused;	/* INET port number (unused) */
	struct in_addr	     capwap_addr;	/* Internet address */

	__u32		         capwap_conn_id;	/* Connection ID of tunnel */

	/* Pad to size of `struct sockaddr'. */
	unsigned char	__pad[sizeof(struct sockaddr) -
			      sizeof(__kernel_sa_family_t) -
			      sizeof(__be16) - sizeof(struct in_addr) -
			      sizeof(__u32)];
};

/*****************************************************************************
 *  NETLINK_GENERIC netlink family.
 *****************************************************************************/

/*
 * Commands.
 * Valid TLVs of each command are:-
 * TUNNEL_CREATE	- CONN_ID, pw_type, netns, ifname, ipinfo, udpinfo, udpcsum, vlanid
 * TUNNEL_DELETE	- CONN_ID
 * TUNNEL_MODIFY	- CONN_ID, udpcsum
 * TUNNEL_GETSTATS	- CONN_ID, (stats)
 * TUNNEL_GET		- CONN_ID, (...)
 * SESSION_CREATE	- SESSION_ID, PW_TYPE, offset, data_seq, cookie, peer_cookie, offset, l2spec
 * SESSION_DELETE	- SESSION_ID
 * SESSION_MODIFY	- SESSION_ID, data_seq
 * SESSION_GET		- SESSION_ID, (...)
 * SESSION_GETSTATS	- SESSION_ID, (stats)
 *
 */
enum {
	CAPWAP_CMD_NOOP,
	CAPWAP_CMD_TUNNEL_CREATE,
	CAPWAP_CMD_TUNNEL_DELETE,
	CAPWAP_CMD_TUNNEL_MODIFY,
	CAPWAP_CMD_TUNNEL_GET,
	CAPWAP_CMD_SESSION_CREATE,
	CAPWAP_CMD_SESSION_DELETE,
	CAPWAP_CMD_SESSION_MODIFY,
	CAPWAP_CMD_SESSION_GET,
	__CAPWAP_CMD_MAX,
};

#define CAPWAP_CMD_MAX			(__CAPWAP_CMD_MAX - 1)

/*
 * ATTR types defined for CAPWAP
 */
enum {
	CAPWAP_ATTR_NONE,			/* no data */
	CAPWAP_ATTR_PW_TYPE,		/* u16, enum capwap_pwtype */
	CAPWAP_ATTR_ENCAP_TYPE,		/* u16, enum capwap_encap_type */
	CAPWAP_ATTR_OFFSET,			/* u16 */
	CAPWAP_ATTR_DATA_SEQ,		/* u16 */
	CAPWAP_ATTR_L2SPEC_TYPE,	/* u8, enum capwap_l2spec_type */
	CAPWAP_ATTR_L2SPEC_LEN,		/* u8, enum capwap_l2spec_type */
	CAPWAP_ATTR_PROTO_VERSION,	/* u8 */
	CAPWAP_ATTR_IFNAME,			/* string */
	CAPWAP_ATTR_CONN_ID,		/* u32 */
	CAPWAP_ATTR_PEER_CONN_ID,	/* u32 */
	CAPWAP_ATTR_SESSION_ID,		/* u32 */
	CAPWAP_ATTR_PEER_SESSION_ID,	/* u32 */
	CAPWAP_ATTR_UDP_CSUM,		/* u8 */
	CAPWAP_ATTR_VLAN_ID,		/* u16 */
	CAPWAP_ATTR_COOKIE,			/* 0, 4 or 8 bytes */
	CAPWAP_ATTR_PEER_COOKIE,	/* 0, 4 or 8 bytes */
	CAPWAP_ATTR_DEBUG,			/* u32 */
	CAPWAP_ATTR_RECV_SEQ,		/* u8 */
	CAPWAP_ATTR_SEND_SEQ,		/* u8 */
	CAPWAP_ATTR_AC_MODE,		/* u8 */
	CAPWAP_ATTR_USING_IPSEC,	/* u8 */
	CAPWAP_ATTR_RECV_TIMEOUT,	/* msec */
	CAPWAP_ATTR_FD,				/* int */
	CAPWAP_ATTR_IP_SADDR,		/* u32 */
	CAPWAP_ATTR_IP_DADDR,		/* u32 */
	CAPWAP_ATTR_UDP_SPORT,		/* u16 */
	CAPWAP_ATTR_UDP_DPORT,		/* u16 */
	CAPWAP_ATTR_MTU,			/* u16 */
	CAPWAP_ATTR_MRU,			/* u16 */
	CAPWAP_ATTR_STATS,			/* nested */
	__CAPWAP_ATTR_MAX,
};

#define CAPWAP_ATTR_MAX			(__CAPWAP_ATTR_MAX - 1)

/* Nested in CAPWAP_ATTR_STATS */
enum {
	CAPWAP_ATTR_STATS_NONE,		/* no data */
	CAPWAP_ATTR_TX_PACKETS,		/* u64 */
	CAPWAP_ATTR_TX_BYTES,		/* u64 */
	CAPWAP_ATTR_TX_ERRORS,		/* u64 */
	CAPWAP_ATTR_RX_PACKETS,		/* u64 */
	CAPWAP_ATTR_RX_BYTES,		/* u64 */
	CAPWAP_ATTR_RX_SEQ_DISCARDS,	/* u64 */
	CAPWAP_ATTR_RX_OOS_PACKETS,	/* u64 */
	CAPWAP_ATTR_RX_ERRORS,		/* u64 */
	__CAPWAP_ATTR_STATS_MAX,
};

#define CAPWAP_ATTR_STATS_MAX		(__CAPWAP_ATTR_STATS_MAX - 1)

enum capwap_pwtype {
	CAPWAP_PWTYPE_NONE = 0x0000,
	CAPWAP_PWTYPE_ETH_VLAN = 0x0004,
	CAPWAP_PWTYPE_ETH = 0x0005,
	CAPWAP_PWTYPE_PPP = 0x0007,
	CAPWAP_PWTYPE_PPP_AC = 0x0008,
	CAPWAP_PWTYPE_IP = 0x000b,
	__CAPWAP_PWTYPE_MAX
};

enum capwap_l2spec_type {
	CAPWAP_L2SPECTYPE_NONE,
	CAPWAP_L2SPECTYPE_DEFAULT,
};

enum capwap_encap_type {
	CAPWAP_ENCAPTYPE_UDP,
	CAPWAP_ENCAPTYPE_IP,
};

enum capwap_seqmode {
	CAPWAP_SEQ_NONE = 0,
	CAPWAP_SEQ_IP = 1,
	CAPWAP_SEQ_ALL = 2,
};

/*
 * NETLINK_GENERIC related info
 */
#define CAPWAP_GENL_NAME		"capwap"
#define CAPWAP_GENL_VERSION	    0x1

#endif
