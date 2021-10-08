 /*****************************************************************************
* Linux CAPWAP Sockets
*
* CAPWAP --- Control And Provisioning of Wireless Access Points (RFC-5415)
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

#ifndef _CAPWAP_CORE_H_
#define _CAPWAP_CORE_H_

/* Just some random numbers */
#define CAPWAP_TUNNEL_MAGIC	    0x42114DDA
#define CAPWAP_SESSION_MAGIC	0x0C04EB7D

/* Per tunnel, session hash table size */
#define CAPWAP_HASH_BITS	4
#define CAPWAP_HASH_SIZE	(1 << CAPWAP_HASH_BITS)

/* System-wide, session hash table size */
#define CAPWAP_HASH_BITS_2	8
#define CAPWAP_HASH_SIZE_2	(1 << CAPWAP_HASH_BITS_2)

/* Debug message categories for the DEBUG socket option */
enum {
	CAPWAP_MSG_DEBUG		= (1 << 0),	/* verbose debug (if
						 * compiled in) */
	CAPWAP_MSG_CONTROL	= (1 << 1),	/* userspace - kernel
						 * interface */
	CAPWAP_MSG_SEQ		= (1 << 2),	/* sequence numbers */
	CAPWAP_MSG_DATA		= (1 << 3),	/* data packets */
};

struct sk_buff;

struct capwap_stats {
	u64			tx_packets;
	u64			tx_bytes;
	u64			tx_errors;
	u64			rx_packets;
	u64			rx_bytes;
//	u64			rx_seq_discards;
	u64			rx_oos_packets;
	u64			rx_errors;
//	u64			rx_cookie_discards;
};

struct capwap_tunnel;

/* Describes a session. Contains information to determine incoming
 * packets and transmit outgoing ones.
 */
struct capwap_session_cfg {
	enum capwap_pwtype	pw_type;
//	unsigned		data_seq:2;	/* data sequencing level
//						 * 0 => none, 1 => IP only,
//						 * 2 => all
//						 */
//	unsigned		recv_seq:1;	/* expect receive packets with
//						 * sequence numbers? */
//	unsigned		send_seq:1;	/* send packets with sequence
//						 * numbers? */
	unsigned		lns_mode:1;	/* behave as LNS? LAC enables
						 * sequence numbers under
						 * control of LNS. */
	int			debug;		/* bitmask of debug message
						 * categories */
	u16			vlan_id;	/* VLAN pseudowire only */
	u16			offset;		/* offset to payload */
//	u16			l2specific_len;	/* Layer 2 specific length */
//	u16			l2specific_type; /* Layer 2 specific type */
//	u8			cookie[8];	/* optional cookie */
//	int			cookie_len;	/* 0, 4 or 8 bytes */
//	u8			peer_cookie[8];	/* peer's cookie */
//	int			peer_cookie_len; /* 0, 4 or 8 bytes */
//	int			reorder_timeout; /* configured reorder timeout
//						  * (in jiffies) */
	int			mtu;
	int			mru;
	char			*ifname;
};

struct capwap_session {
	int			magic;		/* should be
						 * CAPWAP_SESSION_MAGIC */

	struct capwap_tunnel	*tunnel;	/* back pointer to tunnel
						 * context */
	u32			session_id;
	u32			peer_session_id;
//	u8			cookie[8];
//	int			cookie_len;
//	u8			peer_cookie[8];
//	int			peer_cookie_len;
	u16			offset;		/* offset from end of CAPWAP header
						   to beginning of data */
//	u16			l2specific_len;
//	u16			l2specific_type;
	u16			hdr_len;
//	u32			nr;		/* session NR state (receive) */
//	u32			ns;		/* session NR state (send) */
//	struct sk_buff_head	reorder_q;	/* receive reorder queue */
	struct hlist_node	hlist;		/* Hash list node */
	atomic_t		ref_count;

	char			name[32];	/* for logging */
	char			ifname[IFNAMSIZ];
//	unsigned		data_seq:2;	/* data sequencing level
//						 * 0 => none, 1 => IP only,
//						 * 2 => all
//						 */
//	unsigned		recv_seq:1;	/* expect receive packets with
//						 * sequence numbers? */
//	unsigned		send_seq:1;	/* send packets with sequence
//						 * numbers? */
	unsigned		lns_mode:1;	/* behave as LNS? LAC enables
						 * sequence numbers under
						 * control of LNS. */
	int			debug;		/* bitmask of debug message
						 * categories */
//	int			reorder_timeout; /* configured reorder timeout
//						  * (in jiffies) */
	int			mtu;
	int			mru;
	enum capwap_pwtype	pwtype;
	struct capwap_stats	stats;
	struct hlist_node	global_hlist;	/* Global hash list node */

	int (*build_header)(struct capwap_session *session, void *buf);
	void (*recv_skb)(struct capwap_session *session, struct sk_buff *skb, int data_len);
	void (*session_close)(struct capwap_session *session);
	void (*ref)(struct capwap_session *session);
	void (*deref)(struct capwap_session *session);
#if defined(CONFIG_CAPWAP_DEBUGFS) || defined(CONFIG_CAPWAP_DEBUGFS_MODULE)
	void (*show)(struct seq_file *m, void *priv);
#endif
	uint8_t			priv[0];	/* private data */
};

/* Describes the tunnel. It contains info to track all the associated
 * sessions so incoming packets can be sorted out
 */
struct capwap_tunnel_cfg {
	int			debug;		/* bitmask of debug message
						 * categories */
	enum capwap_encap_type	encap;

	/* Used only for kernel-created sockets */
	struct in_addr		local_ip;
	struct in_addr		peer_ip;
	u16			local_udp_port;
	u16			peer_udp_port;
	uint8_t			ac_mode;
	unsigned int		use_udp_checksums:1;
};

struct capwap_tunnel {
	int			magic;		/* Should be CAPWAP_TUNNEL_MAGIC */
	rwlock_t	hlist_lock;	/* protect session_hlist */
	struct hlist_head	session_hlist[CAPWAP_HASH_SIZE];
							/* hashed list of sessions,
						 	* hashed by id */
	u32			tunnel_id;
	u32			peer_tunnel_id;
	int			version;	/* 2=>CAPWAPv2, 3=>CAPWAPv3 */
	int 		ac_mode;    /* AC or WTP mode */
	char		name[20];	/* for logging */
	int			debug;		/* bitmask of debug message
						 	* categories */
	enum capwap_encap_type	encap;
	struct capwap_stats	stats;

	struct list_head	list;	/* Keep a list of all tunnels */
	struct net	*capwap_net;	/* the net we belong to */

	atomic_t	ref_count;
#ifdef CONFIG_DEBUG_FS
	void (*show)(struct seq_file *m, void *arg);
#endif
	int (*recv_payload_hook)(struct sk_buff *skb);
	void (*old_sk_destruct)(struct sock *);
	struct sock		*sock;		/* Parent socket */
	int			fd;

	uint8_t			priv[0];	/* private data */
};

struct _capwap_header
{
    u32 preamble_version:4; // MUST set to zero
    u32 preamble_type:4;
    u32 HLEN:5;
    u32 RID:5;
    u32 WBID:5;
    u32 type:6;
    u32 flags:3;  // MUST set to zero
    u16 fragment_id;
    u16 frag_offset;
    
}__attribute__((__packed__)); 
typedef struct _capwap_header capwap_header_t;

struct capwap_nl_cmd_ops {
	int (*session_create)(struct net *net, u32 tunnel_id, u32 session_id, u32 peer_session_id, struct capwap_session_cfg *cfg);
	int (*session_delete)(struct capwap_session *session);
};

static inline void *capwap_tunnel_priv(struct capwap_tunnel *tunnel)
{
	return &tunnel->priv[0];
}

static inline void *capwap_session_priv(struct capwap_session *session)
{
	return &session->priv[0];
}

static inline struct capwap_tunnel *capwap_sock_to_tunnel(struct sock *sk)
{
	struct capwap_tunnel *tunnel;

	if (sk == NULL)
		return NULL;

	sock_hold(sk);
	tunnel = (struct capwap_tunnel *)(sk->sk_user_data);
	if (tunnel == NULL) {
		sock_put(sk);
		goto out;
	}

	BUG_ON(tunnel->magic != CAPWAP_TUNNEL_MAGIC);

out:
	return tunnel;
}

extern struct capwap_session *capwap_session_find(struct net *net, struct capwap_tunnel *tunnel, u32 session_id);
extern struct capwap_session *capwap_session_find_nth(struct capwap_tunnel *tunnel, int nth);
extern struct capwap_session *capwap_session_find_by_ifname(struct net *net, char *ifname);
extern struct capwap_tunnel *capwap_tunnel_find(struct net *net, u32 tunnel_id);
extern struct capwap_tunnel *capwap_tunnel_find_nth(struct net *net, int nth);

extern int capwap_tunnel_create(struct net *net, int fd, int version, u32 tunnel_id, u32 peer_tunnel_id, struct capwap_tunnel_cfg *cfg, struct capwap_tunnel **tunnelp);
extern int capwap_tunnel_delete(struct capwap_tunnel *tunnel);
extern struct capwap_session *capwap_session_create(int priv_size, struct capwap_tunnel *tunnel, u32 session_id, u32 peer_session_id, struct capwap_session_cfg *cfg);
extern int capwap_session_delete(struct capwap_session *session);
extern void capwap_session_free(struct capwap_session *session);
extern void capwap_recv_common(struct capwap_session *session, struct sk_buff *skb, unsigned char *ptr, unsigned char *optr, u16 hdrflags, int length, int (*payload_hook)(struct sk_buff *skb));
extern int capwap_udp_encap_recv(struct sock *sk, struct sk_buff *skb);

extern int capwap_xmit_skb(struct capwap_session *session, struct sk_buff *skb, int hdr_len);

extern int capwap_nl_register_ops(enum capwap_pwtype pw_type, const struct capwap_nl_cmd_ops *ops);
extern void capwap_nl_unregister_ops(enum capwap_pwtype pw_type);

/* Session reference counts. Incremented when code obtains a reference
 * to a session.
 */
static inline void capwap_session_inc_refcount_1(struct capwap_session *session)
{
	atomic_inc(&session->ref_count);
}

static inline void capwap_session_dec_refcount_1(struct capwap_session *session)
{
	if (atomic_dec_and_test(&session->ref_count))
		capwap_session_free(session);
}

#ifdef CAPWAP_REFCNT_DEBUG
#define capwap_session_inc_refcount(_s) do { \
		printk(KERN_DEBUG "capwap_session_inc_refcount: %s:%d %s: cnt=%d\n", __func__, __LINE__, (_s)->name, atomic_read(&_s->ref_count)); \
		capwap_session_inc_refcount_1(_s);				\
	} while (0)
#define capwap_session_dec_refcount(_s) do { \
		printk(KERN_DEBUG "capwap_session_dec_refcount: %s:%d %s: cnt=%d\n", __func__, __LINE__, (_s)->name, atomic_read(&_s->ref_count)); \
		capwap_session_dec_refcount_1(_s);				\
	} while (0)
#else
#define capwap_session_inc_refcount(s) capwap_session_inc_refcount_1(s)
#define capwap_session_dec_refcount(s) capwap_session_dec_refcount_1(s)
#endif

#endif /* _CAPWAP_CORE_H_ */
