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

#include <net/sock.h>
#include <net/genetlink.h>
#include <net/udp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <linux/list.h>
#include <net/net_namespace.h>

//#include <linux/capwap.h>
#include "capwap.h"
#include "capwap_core.h"


static struct genl_family capwap_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= CAPWAP_GENL_NAME,
	.version	= CAPWAP_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= CAPWAP_ATTR_MAX,
};

/* Accessed under genl lock */
static const struct capwap_nl_cmd_ops *capwap_nl_cmd_ops[__CAPWAP_PWTYPE_MAX];

static struct capwap_session *capwap_nl_session_find(struct genl_info *info)
{
	u32 tunnel_id;
	u32 session_id;
	char *ifname;
	struct capwap_tunnel *tunnel;
	struct capwap_session *session = NULL;
	struct net *net = genl_info_net(info);

	if (info->attrs[CAPWAP_ATTR_IFNAME]) {
		ifname = nla_data(info->attrs[CAPWAP_ATTR_IFNAME]);
		session = capwap_session_find_by_ifname(net, ifname);
	} else if ((info->attrs[CAPWAP_ATTR_SESSION_ID]) &&
		   (info->attrs[CAPWAP_ATTR_CONN_ID])) {
		tunnel_id = nla_get_u32(info->attrs[CAPWAP_ATTR_CONN_ID]);
		session_id = nla_get_u32(info->attrs[CAPWAP_ATTR_SESSION_ID]);
		tunnel = capwap_tunnel_find(net, tunnel_id);
		if (tunnel)
			session = capwap_session_find(net, tunnel, session_id);
	}

	return session;
}

static int capwap_nl_cmd_noop(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	int ret = -ENOBUFS;

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq,
			  &capwap_nl_family, 0, CAPWAP_CMD_NOOP);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto err_out;
	}

	genlmsg_end(msg, hdr);

	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);

err_out:
	nlmsg_free(msg);

out:
	return ret;
}

static int capwap_nl_cmd_tunnel_create(struct sk_buff *skb, struct genl_info *info)
{
	u32 tunnel_id;
	u32 peer_tunnel_id;
	int proto_version;
	int fd;
	int ret = 0;
	struct capwap_tunnel_cfg cfg = { 0, };
	struct capwap_tunnel *tunnel;
	struct net *net = genl_info_net(info);
	if (!info->attrs[CAPWAP_ATTR_CONN_ID]) {
		ret = -EINVAL;
		goto out;
	}
	tunnel_id = nla_get_u32(info->attrs[CAPWAP_ATTR_CONN_ID]);
	if (!info->attrs[CAPWAP_ATTR_PEER_CONN_ID]) {
		ret = -EINVAL;
		goto out;
	}
	peer_tunnel_id = nla_get_u32(info->attrs[CAPWAP_ATTR_PEER_CONN_ID]);
	if (!info->attrs[CAPWAP_ATTR_PROTO_VERSION]) {
		ret = -EINVAL;
		goto out;
	}
	proto_version = nla_get_u8(info->attrs[CAPWAP_ATTR_PROTO_VERSION]);
	if (!info->attrs[CAPWAP_ATTR_ENCAP_TYPE]) {
		ret = -EINVAL;
		goto out;
	}
	cfg.encap = nla_get_u16(info->attrs[CAPWAP_ATTR_ENCAP_TYPE]);
	fd = -1;
	if (info->attrs[CAPWAP_ATTR_FD]) {
		fd = nla_get_u32(info->attrs[CAPWAP_ATTR_FD]);
	} else {
		if (info->attrs[CAPWAP_ATTR_IP_SADDR])
			cfg.local_ip.s_addr = nla_get_be32(info->attrs[CAPWAP_ATTR_IP_SADDR]);
		if (info->attrs[CAPWAP_ATTR_IP_DADDR])
			cfg.peer_ip.s_addr = nla_get_be32(info->attrs[CAPWAP_ATTR_IP_DADDR]);
		if (info->attrs[CAPWAP_ATTR_UDP_SPORT])
			cfg.local_udp_port = nla_get_u16(info->attrs[CAPWAP_ATTR_UDP_SPORT]);
		if (info->attrs[CAPWAP_ATTR_UDP_DPORT])
			cfg.peer_udp_port = nla_get_u16(info->attrs[CAPWAP_ATTR_UDP_DPORT]);
		if (info->attrs[CAPWAP_ATTR_UDP_CSUM])
			cfg.use_udp_checksums = nla_get_flag(info->attrs[CAPWAP_ATTR_UDP_CSUM]);
	}
	if (info->attrs[CAPWAP_ATTR_DEBUG])
		cfg.debug = nla_get_u32(info->attrs[CAPWAP_ATTR_DEBUG]);
	if (info->attrs[CAPWAP_ATTR_AC_MODE])
		cfg.ac_mode = nla_get_u8(info->attrs[CAPWAP_ATTR_AC_MODE]);
	
	tunnel = capwap_tunnel_find(net, tunnel_id);
	if (tunnel != NULL) {
		ret = -EEXIST;
		goto out;
	}
	ret = -EINVAL;
	switch (cfg.encap) {
	case CAPWAP_ENCAPTYPE_UDP:
	case CAPWAP_ENCAPTYPE_IP:
		ret = capwap_tunnel_create(net, fd, proto_version, tunnel_id,
					 peer_tunnel_id, &cfg, &tunnel);
		break;
	}
out:
	return ret;
}

static int capwap_nl_cmd_tunnel_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct capwap_tunnel *tunnel;
	u32 tunnel_id;
	int ret = 0;
	struct net *net = genl_info_net(info);

	if (!info->attrs[CAPWAP_ATTR_CONN_ID]) {
		ret = -EINVAL;
		goto out;
	}
	tunnel_id = nla_get_u32(info->attrs[CAPWAP_ATTR_CONN_ID]);

	tunnel = capwap_tunnel_find(net, tunnel_id);
	if (tunnel == NULL) {
		ret = -ENODEV;
		goto out;
	}

	(void) capwap_tunnel_delete(tunnel);

out:
	return ret;
}

static int capwap_nl_cmd_tunnel_modify(struct sk_buff *skb, struct genl_info *info)
{
	struct capwap_tunnel *tunnel;
	u32 tunnel_id;
	int ret = 0;
	struct net *net = genl_info_net(info);

	if (!info->attrs[CAPWAP_ATTR_CONN_ID]) {
		ret = -EINVAL;
		goto out;
	}
	tunnel_id = nla_get_u32(info->attrs[CAPWAP_ATTR_CONN_ID]);

	tunnel = capwap_tunnel_find(net, tunnel_id);
	if (tunnel == NULL) {
		ret = -ENODEV;
		goto out;
	}

	if (info->attrs[CAPWAP_ATTR_DEBUG])
		tunnel->debug = nla_get_u32(info->attrs[CAPWAP_ATTR_DEBUG]);

out:
	return ret;
}

static int capwap_nl_tunnel_send(struct sk_buff *skb, u32 pid, u32 seq, int flags,
			       struct capwap_tunnel *tunnel)
{
	void *hdr;
	struct nlattr *nest;
	struct sock *sk = NULL;
	struct inet_sock *inet;

	hdr = genlmsg_put(skb, pid, seq, &capwap_nl_family, flags,
			  CAPWAP_CMD_TUNNEL_GET);
	if (IS_ERR(hdr))
		return PTR_ERR(hdr);

	NLA_PUT_U8(skb, CAPWAP_ATTR_PROTO_VERSION, tunnel->version);
	NLA_PUT_U32(skb, CAPWAP_ATTR_CONN_ID, tunnel->tunnel_id);
	NLA_PUT_U32(skb, CAPWAP_ATTR_PEER_CONN_ID, tunnel->peer_tunnel_id);
	NLA_PUT_U32(skb, CAPWAP_ATTR_DEBUG, tunnel->debug);
	NLA_PUT_U16(skb, CAPWAP_ATTR_ENCAP_TYPE, tunnel->encap);
	NLA_PUT_U8(skb, CAPWAP_ATTR_AC_MODE, tunnel->ac_mode);

	nest = nla_nest_start(skb, CAPWAP_ATTR_STATS);
	if (nest == NULL)
		goto nla_put_failure;

	NLA_PUT_U64(skb, CAPWAP_ATTR_TX_PACKETS, tunnel->stats.tx_packets);
	NLA_PUT_U64(skb, CAPWAP_ATTR_TX_BYTES, tunnel->stats.tx_bytes);
	NLA_PUT_U64(skb, CAPWAP_ATTR_TX_ERRORS, tunnel->stats.tx_errors);
	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_PACKETS, tunnel->stats.rx_packets);
	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_BYTES, tunnel->stats.rx_bytes);
//	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_SEQ_DISCARDS, tunnel->stats.rx_seq_discards);
	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_OOS_PACKETS, tunnel->stats.rx_oos_packets);
	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_ERRORS, tunnel->stats.rx_errors);
	nla_nest_end(skb, nest);

	sk = tunnel->sock;
	if (!sk)
		goto out;

	inet = inet_sk(sk);

	switch (tunnel->encap) {
	case CAPWAP_ENCAPTYPE_UDP:
		NLA_PUT_U16(skb, CAPWAP_ATTR_UDP_SPORT, ntohs(inet->inet_sport));
		NLA_PUT_U16(skb, CAPWAP_ATTR_UDP_DPORT, ntohs(inet->inet_dport));
		NLA_PUT_U8(skb, CAPWAP_ATTR_UDP_CSUM, (sk->sk_no_check != UDP_CSUM_NOXMIT));
		/* NOBREAK */
	case CAPWAP_ENCAPTYPE_IP:
		NLA_PUT_BE32(skb, CAPWAP_ATTR_IP_SADDR, inet->inet_saddr);
		NLA_PUT_BE32(skb, CAPWAP_ATTR_IP_DADDR, inet->inet_daddr);
		break;
	}

out:
	return genlmsg_end(skb, hdr);

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int capwap_nl_cmd_tunnel_get(struct sk_buff *skb, struct genl_info *info)
{
	struct capwap_tunnel *tunnel;
	struct sk_buff *msg;
	u32 tunnel_id;
	int ret = -ENOBUFS;
	struct net *net = genl_info_net(info);

	if (!info->attrs[CAPWAP_ATTR_CONN_ID]) {
		ret = -EINVAL;
		goto out;
	}

	tunnel_id = nla_get_u32(info->attrs[CAPWAP_ATTR_CONN_ID]);

	tunnel = capwap_tunnel_find(net, tunnel_id);
	if (tunnel == NULL) {
		ret = -ENODEV;
		goto out;
	}

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

	ret = capwap_nl_tunnel_send(msg, info->snd_pid, info->snd_seq,
				  NLM_F_ACK, tunnel);
	if (ret < 0)
		goto err_out;

	return genlmsg_unicast(net, msg, info->snd_pid);

err_out:
	nlmsg_free(msg);

out:
	return ret;
}

static int capwap_nl_cmd_tunnel_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int ti = cb->args[0];
	struct capwap_tunnel *tunnel;
	struct net *net = sock_net(skb->sk);

	for (;;) {
		tunnel = capwap_tunnel_find_nth(net, ti);
		if (tunnel == NULL)
			goto out;

		if (capwap_nl_tunnel_send(skb, NETLINK_CB(cb->skb).pid,
					cb->nlh->nlmsg_seq, NLM_F_MULTI,
					tunnel) <= 0)
			goto out;

		ti++;
	}

out:
	cb->args[0] = ti;

	return skb->len;
}

static int capwap_nl_cmd_session_create(struct sk_buff *skb, struct genl_info *info)
{
	u32 tunnel_id = 0;
	u32 session_id;
	u32 peer_session_id;
	int ret = 0;
	struct capwap_tunnel *tunnel;
	struct capwap_session *session;
	struct capwap_session_cfg cfg = { 0, };
	struct net *net = genl_info_net(info);
	if (!info->attrs[CAPWAP_ATTR_CONN_ID]) {
		ret = -EINVAL;
		goto out;
	}
	tunnel_id = nla_get_u32(info->attrs[CAPWAP_ATTR_CONN_ID]);
	tunnel = capwap_tunnel_find(net, tunnel_id);
	if (!tunnel) {
		ret = -ENODEV;
		goto out;
	}

	if (!info->attrs[CAPWAP_ATTR_SESSION_ID]) {
		ret = -EINVAL;
		goto out;
	}
	session_id = nla_get_u32(info->attrs[CAPWAP_ATTR_SESSION_ID]);
	session = capwap_session_find(net, tunnel, session_id);
	if (session) {
		ret = -EEXIST;
		goto out;
	}

	if (!info->attrs[CAPWAP_ATTR_PEER_SESSION_ID]) {
		ret = -EINVAL;
		goto out;
	}
	peer_session_id = nla_get_u32(info->attrs[CAPWAP_ATTR_PEER_SESSION_ID]);

	if (!info->attrs[CAPWAP_ATTR_PW_TYPE]) {
		ret = -EINVAL;
		goto out;
	}
	cfg.pw_type = nla_get_u16(info->attrs[CAPWAP_ATTR_PW_TYPE]);
	if (cfg.pw_type >= __CAPWAP_PWTYPE_MAX) {
		ret = -EINVAL;
		goto out;
	}

	if (tunnel->version > 2) {
		if (info->attrs[CAPWAP_ATTR_OFFSET])
			cfg.offset = nla_get_u16(info->attrs[CAPWAP_ATTR_OFFSET]);

//		if (info->attrs[CAPWAP_ATTR_DATA_SEQ])
//			cfg.data_seq = nla_get_u8(info->attrs[CAPWAP_ATTR_DATA_SEQ]);

//		cfg.l2specific_type = CAPWAP_L2SPECTYPE_DEFAULT;
//		if (info->attrs[CAPWAP_ATTR_L2SPEC_TYPE])
//			cfg.l2specific_type = nla_get_u8(info->attrs[CAPWAP_ATTR_L2SPEC_TYPE]);

//		cfg.l2specific_len = 4;
//		if (info->attrs[CAPWAP_ATTR_L2SPEC_LEN])
//			cfg.l2specific_len = nla_get_u8(info->attrs[CAPWAP_ATTR_L2SPEC_LEN]);

//		if (info->attrs[CAPWAP_ATTR_COOKIE]) {
//			u16 len = nla_len(info->attrs[CAPWAP_ATTR_COOKIE]);
//			if (len > 8) {
//				ret = -EINVAL;
//				goto out;
//			}
//			cfg.cookie_len = len;
//			memcpy(&cfg.cookie[0], nla_data(info->attrs[CAPWAP_ATTR_COOKIE]), len);
//		}
//		if (info->attrs[CAPWAP_ATTR_PEER_COOKIE]) {
//			u16 len = nla_len(info->attrs[CAPWAP_ATTR_PEER_COOKIE]);
//			if (len > 8) {
//				ret = -EINVAL;
//				goto out;
//			}
//			cfg.peer_cookie_len = len;
//			memcpy(&cfg.peer_cookie[0], nla_data(info->attrs[CAPWAP_ATTR_PEER_COOKIE]), len);
//		}
		if (info->attrs[CAPWAP_ATTR_IFNAME])
			cfg.ifname = nla_data(info->attrs[CAPWAP_ATTR_IFNAME]);

		if (info->attrs[CAPWAP_ATTR_VLAN_ID])
			cfg.vlan_id = nla_get_u16(info->attrs[CAPWAP_ATTR_VLAN_ID]);
	}

	if (info->attrs[CAPWAP_ATTR_DEBUG])
		cfg.debug = nla_get_u32(info->attrs[CAPWAP_ATTR_DEBUG]);

//	if (info->attrs[CAPWAP_ATTR_RECV_SEQ])
//		cfg.recv_seq = nla_get_u8(info->attrs[CAPWAP_ATTR_RECV_SEQ]);

//	if (info->attrs[CAPWAP_ATTR_SEND_SEQ])
//		cfg.send_seq = nla_get_u8(info->attrs[CAPWAP_ATTR_SEND_SEQ]);

//	if (info->attrs[CAPWAP_ATTR_LNS_MODE])
//		cfg.lns_mode = nla_get_u8(info->attrs[CAPWAP_ATTR_LNS_MODE]);

//	if (info->attrs[CAPWAP_ATTR_RECV_TIMEOUT])
//		cfg.reorder_timeout = nla_get_msecs(info->attrs[CAPWAP_ATTR_RECV_TIMEOUT]);

	if (info->attrs[CAPWAP_ATTR_MTU])
		cfg.mtu = nla_get_u16(info->attrs[CAPWAP_ATTR_MTU]);

	if (info->attrs[CAPWAP_ATTR_MRU])
		cfg.mru = nla_get_u16(info->attrs[CAPWAP_ATTR_MRU]);

	if ((capwap_nl_cmd_ops[cfg.pw_type] == NULL) ||
	    (capwap_nl_cmd_ops[cfg.pw_type]->session_create == NULL)) {
		ret = -EPROTONOSUPPORT;
		goto out;
	}

	/* Check that pseudowire-specific params are present */
	switch (cfg.pw_type) {
	case CAPWAP_PWTYPE_NONE:
		break;
	case CAPWAP_PWTYPE_ETH_VLAN:
		if (!info->attrs[CAPWAP_ATTR_VLAN_ID]) {
			ret = -EINVAL;
			goto out;
		}
		break;
	case CAPWAP_PWTYPE_ETH:
		break;
	case CAPWAP_PWTYPE_PPP:
	case CAPWAP_PWTYPE_PPP_AC:
		break;
	case CAPWAP_PWTYPE_IP:
	default:
		ret = -EPROTONOSUPPORT;
		break;
	}

	ret = -EPROTONOSUPPORT;
	if (capwap_nl_cmd_ops[cfg.pw_type]->session_create)
		ret = (*capwap_nl_cmd_ops[cfg.pw_type]->session_create)(net, tunnel_id,
			session_id, peer_session_id, &cfg);

out:
	return ret;
}

static int capwap_nl_cmd_session_delete(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	struct capwap_session *session;
	u16 pw_type;

	session = capwap_nl_session_find(info);
	if (session == NULL) {
		ret = -ENODEV;
		goto out;
	}

	pw_type = session->pwtype;
	if (pw_type < __CAPWAP_PWTYPE_MAX)
		if (capwap_nl_cmd_ops[pw_type] && capwap_nl_cmd_ops[pw_type]->session_delete)
			ret = (*capwap_nl_cmd_ops[pw_type]->session_delete)(session);

out:
	return ret;
}

static int capwap_nl_cmd_session_modify(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	struct capwap_session *session;

	session = capwap_nl_session_find(info);
	if (session == NULL) {
		ret = -ENODEV;
		goto out;
	}

	if (info->attrs[CAPWAP_ATTR_DEBUG])
		session->debug = nla_get_u32(info->attrs[CAPWAP_ATTR_DEBUG]);

//	if (info->attrs[CAPWAP_ATTR_DATA_SEQ])
//		session->data_seq = nla_get_u8(info->attrs[CAPWAP_ATTR_DATA_SEQ]);

//	if (info->attrs[CAPWAP_ATTR_RECV_SEQ])
//		session->recv_seq = nla_get_u8(info->attrs[CAPWAP_ATTR_RECV_SEQ]);

//	if (info->attrs[CAPWAP_ATTR_SEND_SEQ])
//		session->send_seq = nla_get_u8(info->attrs[CAPWAP_ATTR_SEND_SEQ]);

//	if (info->attrs[CAPWAP_ATTR_LNS_MODE])
//		session->lns_mode = nla_get_u8(info->attrs[CAPWAP_ATTR_LNS_MODE]);

//	if (info->attrs[CAPWAP_ATTR_RECV_TIMEOUT])
//		session->reorder_timeout = nla_get_msecs(info->attrs[CAPWAP_ATTR_RECV_TIMEOUT]);

	if (info->attrs[CAPWAP_ATTR_MTU])
		session->mtu = nla_get_u16(info->attrs[CAPWAP_ATTR_MTU]);

	if (info->attrs[CAPWAP_ATTR_MRU])
		session->mru = nla_get_u16(info->attrs[CAPWAP_ATTR_MRU]);

out:
	return ret;
}

static int capwap_nl_session_send(struct sk_buff *skb, u32 pid, u32 seq, int flags,
				struct capwap_session *session)
{
	void *hdr;
	struct nlattr *nest;
	struct capwap_tunnel *tunnel = session->tunnel;
	struct sock *sk = NULL;

	sk = tunnel->sock;

	hdr = genlmsg_put(skb, pid, seq, &capwap_nl_family, flags, CAPWAP_CMD_SESSION_GET);
	if (IS_ERR(hdr))
		return PTR_ERR(hdr);

	NLA_PUT_U32(skb, CAPWAP_ATTR_CONN_ID, tunnel->tunnel_id);
	NLA_PUT_U32(skb, CAPWAP_ATTR_SESSION_ID, session->session_id);
	NLA_PUT_U32(skb, CAPWAP_ATTR_PEER_CONN_ID, tunnel->peer_tunnel_id);
	NLA_PUT_U32(skb, CAPWAP_ATTR_PEER_SESSION_ID, session->peer_session_id);
	NLA_PUT_U32(skb, CAPWAP_ATTR_DEBUG, session->debug);
	NLA_PUT_U16(skb, CAPWAP_ATTR_PW_TYPE, session->pwtype);
	NLA_PUT_U16(skb, CAPWAP_ATTR_MTU, session->mtu);
	if (session->mru)
		NLA_PUT_U16(skb, CAPWAP_ATTR_MRU, session->mru);

	if (session->ifname && session->ifname[0])
		NLA_PUT_STRING(skb, CAPWAP_ATTR_IFNAME, session->ifname);
//	if (session->cookie_len)
//		NLA_PUT(skb, CAPWAP_ATTR_COOKIE, session->cookie_len, &session->cookie[0]);
//	if (session->peer_cookie_len)
//		NLA_PUT(skb, CAPWAP_ATTR_PEER_COOKIE, session->peer_cookie_len, &session->peer_cookie[0]);
//	NLA_PUT_U8(skb, CAPWAP_ATTR_RECV_SEQ, session->recv_seq);
//	NLA_PUT_U8(skb, CAPWAP_ATTR_SEND_SEQ, session->send_seq);
//	NLA_PUT_U8(skb, CAPWAP_ATTR_LNS_MODE, session->lns_mode);
#ifdef CONFIG_XFRM
	if ((sk) && (sk->sk_policy[0] || sk->sk_policy[1]))
		NLA_PUT_U8(skb, CAPWAP_ATTR_USING_IPSEC, 1);
#endif
//	if (session->reorder_timeout)
//		NLA_PUT_MSECS(skb, CAPWAP_ATTR_RECV_TIMEOUT, session->reorder_timeout);

	nest = nla_nest_start(skb, CAPWAP_ATTR_STATS);
	if (nest == NULL)
		goto nla_put_failure;
	NLA_PUT_U64(skb, CAPWAP_ATTR_TX_PACKETS, session->stats.tx_packets);
	NLA_PUT_U64(skb, CAPWAP_ATTR_TX_BYTES, session->stats.tx_bytes);
	NLA_PUT_U64(skb, CAPWAP_ATTR_TX_ERRORS, session->stats.tx_errors);
	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_PACKETS, session->stats.rx_packets);
	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_BYTES, session->stats.rx_bytes);
//	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_SEQ_DISCARDS, session->stats.rx_seq_discards);
	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_OOS_PACKETS, session->stats.rx_oos_packets);
	NLA_PUT_U64(skb, CAPWAP_ATTR_RX_ERRORS, session->stats.rx_errors);
	nla_nest_end(skb, nest);

	return genlmsg_end(skb, hdr);

 nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int capwap_nl_cmd_session_get(struct sk_buff *skb, struct genl_info *info)
{
	struct capwap_session *session;
	struct sk_buff *msg;
	int ret;

	session = capwap_nl_session_find(info);
	if (session == NULL) {
		ret = -ENODEV;
		goto out;
	}

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

	ret = capwap_nl_session_send(msg, info->snd_pid, info->snd_seq,
				   0, session);
	if (ret < 0)
		goto err_out;

	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);

err_out:
	nlmsg_free(msg);

out:
	return ret;
}

static int capwap_nl_cmd_session_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct capwap_session *session;
	struct capwap_tunnel *tunnel = NULL;
	int ti = cb->args[0];
	int si = cb->args[1];

	for (;;) {
		if (tunnel == NULL) {
			tunnel = capwap_tunnel_find_nth(net, ti);
			if (tunnel == NULL)
				goto out;
		}

		session = capwap_session_find_nth(tunnel, si);
		if (session == NULL) {
			ti++;
			tunnel = NULL;
			si = 0;
			continue;
		}

		if (capwap_nl_session_send(skb, NETLINK_CB(cb->skb).pid,
					 cb->nlh->nlmsg_seq, NLM_F_MULTI,
					 session) <= 0)
			break;

		si++;
	}

out:
	cb->args[0] = ti;
	cb->args[1] = si;

	return skb->len;
}

static struct nla_policy capwap_nl_policy[CAPWAP_ATTR_MAX + 1] = {
	[CAPWAP_ATTR_NONE]		= { .type = NLA_UNSPEC, },
	[CAPWAP_ATTR_PW_TYPE]		= { .type = NLA_U16, },
	[CAPWAP_ATTR_ENCAP_TYPE]		= { .type = NLA_U16, },
	[CAPWAP_ATTR_OFFSET]		= { .type = NLA_U16, },
	[CAPWAP_ATTR_DATA_SEQ]		= { .type = NLA_U8, },
	[CAPWAP_ATTR_L2SPEC_TYPE]		= { .type = NLA_U8, },
	[CAPWAP_ATTR_L2SPEC_LEN]		= { .type = NLA_U8, },
	[CAPWAP_ATTR_PROTO_VERSION]	= { .type = NLA_U8, },
	[CAPWAP_ATTR_CONN_ID]		= { .type = NLA_U32, },
	[CAPWAP_ATTR_PEER_CONN_ID]	= { .type = NLA_U32, },
	[CAPWAP_ATTR_SESSION_ID]		= { .type = NLA_U32, },
	[CAPWAP_ATTR_PEER_SESSION_ID]	= { .type = NLA_U32, },
	[CAPWAP_ATTR_UDP_CSUM]		= { .type = NLA_U8, },
	[CAPWAP_ATTR_VLAN_ID]		= { .type = NLA_U16, },
	[CAPWAP_ATTR_DEBUG]		= { .type = NLA_U32, },
	[CAPWAP_ATTR_RECV_SEQ]		= { .type = NLA_U8, },
	[CAPWAP_ATTR_SEND_SEQ]		= { .type = NLA_U8, },
	[CAPWAP_ATTR_AC_MODE]		= { .type = NLA_U8, },
	[CAPWAP_ATTR_USING_IPSEC]		= { .type = NLA_U8, },
	[CAPWAP_ATTR_RECV_TIMEOUT]	= { .type = NLA_MSECS, },
	[CAPWAP_ATTR_FD]			= { .type = NLA_U32, },
	[CAPWAP_ATTR_IP_SADDR]		= { .type = NLA_U32, },
	[CAPWAP_ATTR_IP_DADDR]		= { .type = NLA_U32, },
	[CAPWAP_ATTR_UDP_SPORT]		= { .type = NLA_U16, },
	[CAPWAP_ATTR_UDP_DPORT]		= { .type = NLA_U16, },
	[CAPWAP_ATTR_MTU]			= { .type = NLA_U16, },
	[CAPWAP_ATTR_MRU]			= { .type = NLA_U16, },
	[CAPWAP_ATTR_STATS]		= { .type = NLA_NESTED, },
	[CAPWAP_ATTR_IFNAME] = {
		.type = NLA_NUL_STRING,
		.len = IFNAMSIZ - 1,
	},
	[CAPWAP_ATTR_COOKIE] = {
		.type = NLA_BINARY,
		.len = 8,
	},
	[CAPWAP_ATTR_PEER_COOKIE] = {
		.type = NLA_BINARY,
		.len = 8,
	},
};

static struct genl_ops capwap_nl_ops[] = {
	{
		.cmd = CAPWAP_CMD_NOOP,
		.doit = capwap_nl_cmd_noop,
		.policy = capwap_nl_policy,
		/* can be retrieved by unprivileged users */
	},
	{
		.cmd = CAPWAP_CMD_TUNNEL_CREATE,
		.doit = capwap_nl_cmd_tunnel_create,
		.policy = capwap_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CAPWAP_CMD_TUNNEL_DELETE,
		.doit = capwap_nl_cmd_tunnel_delete,
		.policy = capwap_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CAPWAP_CMD_TUNNEL_MODIFY,
		.doit = capwap_nl_cmd_tunnel_modify,
		.policy = capwap_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CAPWAP_CMD_TUNNEL_GET,
		.doit = capwap_nl_cmd_tunnel_get,
		.dumpit = capwap_nl_cmd_tunnel_dump,
		.policy = capwap_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CAPWAP_CMD_SESSION_CREATE,
		.doit = capwap_nl_cmd_session_create,
		.policy = capwap_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CAPWAP_CMD_SESSION_DELETE,
		.doit = capwap_nl_cmd_session_delete,
		.policy = capwap_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CAPWAP_CMD_SESSION_MODIFY,
		.doit = capwap_nl_cmd_session_modify,
		.policy = capwap_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CAPWAP_CMD_SESSION_GET,
		.doit = capwap_nl_cmd_session_get,
		.dumpit = capwap_nl_cmd_session_dump,
		.policy = capwap_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

int capwap_nl_register_ops(enum capwap_pwtype pw_type, const struct capwap_nl_cmd_ops *ops)
{
	int ret;

	ret = -EINVAL;
	if (pw_type >= __CAPWAP_PWTYPE_MAX)
		goto err;

	genl_lock();
	ret = -EBUSY;
	if (capwap_nl_cmd_ops[pw_type])
		goto out;

	capwap_nl_cmd_ops[pw_type] = ops;
	ret = 0;

out:
	genl_unlock();
err:
	return ret;
}
EXPORT_SYMBOL_GPL(capwap_nl_register_ops);

void capwap_nl_unregister_ops(enum capwap_pwtype pw_type)
{
	if (pw_type < __CAPWAP_PWTYPE_MAX) {
		genl_lock();
		capwap_nl_cmd_ops[pw_type] = NULL;
		genl_unlock();
	}
}
EXPORT_SYMBOL_GPL(capwap_nl_unregister_ops);

static int capwap_nl_init(void)
{
	int err;

	printk(KERN_INFO "CAPWAP netlink interface\n");
	err = genl_register_family_with_ops(&capwap_nl_family, capwap_nl_ops,
					    ARRAY_SIZE(capwap_nl_ops));

	return err;
}

static void capwap_nl_cleanup(void)
{
	genl_unregister_family(&capwap_nl_family);
}

module_init(capwap_nl_init);
module_exit(capwap_nl_cleanup);

MODULE_AUTHOR("James Chapman <jchapman@katalix.com>");
MODULE_DESCRIPTION("CAPWAP netlink");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_ALIAS("net-pf-" __stringify(PF_NETLINK) "-proto-" \
	     __stringify(NETLINK_GENERIC) "-type-" "capwap");
