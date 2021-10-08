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

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/hash.h>
#include <linux/capwap.h>
#include <linux/in.h>
#include <linux/etherdevice.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/tcp_states.h>
#include <net/protocol.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "capwap_core.h"

static struct dentry *rootdir;
static struct dentry *tunnels;

struct capwap_dfs_seq_data {
	struct net *net;
	int tunnel_idx;			/* current tunnel */
	int session_idx;		/* index of session within current tunnel */
	struct capwap_tunnel *tunnel;
	struct capwap_session *session;	/* NULL means get next tunnel */
};

static void capwap_dfs_next_tunnel(struct capwap_dfs_seq_data *pd)
{
	pd->tunnel = capwap_tunnel_find_nth(pd->net, pd->tunnel_idx);
	pd->tunnel_idx++;
}

static void capwap_dfs_next_session(struct capwap_dfs_seq_data *pd)
{
	pd->session = capwap_session_find_nth(pd->tunnel, pd->session_idx);
	pd->session_idx++;

	if (pd->session == NULL) {
		pd->session_idx = 0;
		capwap_dfs_next_tunnel(pd);
	}

}

static void *capwap_dfs_seq_start(struct seq_file *m, loff_t *offs)
{
	struct capwap_dfs_seq_data *pd = SEQ_START_TOKEN;
	loff_t pos = *offs;

	if (!pos)
		goto out;

	BUG_ON(m->private == NULL);
	pd = m->private;

	if (pd->tunnel == NULL)
		capwap_dfs_next_tunnel(pd);
	else
		capwap_dfs_next_session(pd);

	/* NULL tunnel and session indicates end of list */
	if ((pd->tunnel == NULL) && (pd->session == NULL))
		pd = NULL;

out:
	return pd;
}


static void *capwap_dfs_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void capwap_dfs_seq_stop(struct seq_file *p, void *v)
{
	/* nothing to do */
}

static void capwap_dfs_seq_tunnel_show(struct seq_file *m, void *v)
{
	struct capwap_tunnel *tunnel = v;
	int session_count = 0;
	int hash;
	struct hlist_node *walk;
	struct hlist_node *tmp;

	read_lock_bh(&tunnel->hlist_lock);
	for (hash = 0; hash < CAPWAP_HASH_SIZE; hash++) {
		hlist_for_each_safe(walk, tmp, &tunnel->session_hlist[hash]) {
			struct capwap_session *session;

			session = hlist_entry(walk, struct capwap_session, hlist);
			if (session->session_id == 0)
				continue;

			session_count++;
		}
	}
	read_unlock_bh(&tunnel->hlist_lock);

	seq_printf(m, "\nTUNNEL %u peer %u", tunnel->tunnel_id, tunnel->peer_tunnel_id);
	if (tunnel->sock) {
		struct inet_sock *inet = inet_sk(tunnel->sock);
		seq_printf(m, " from %pI4 to %pI4\n",
			   &inet->inet_saddr, &inet->inet_daddr);
		if (tunnel->encap == CAPWAP_ENCAPTYPE_UDP)
			seq_printf(m, " source port %hu, dest port %hu\n",
				   ntohs(inet->inet_sport), ntohs(inet->inet_dport));
	}
	seq_printf(m, " CAPWAPv%d, %s\n", tunnel->version,
		   tunnel->encap == CAPWAP_ENCAPTYPE_UDP ? "UDP" :
		   tunnel->encap == CAPWAP_ENCAPTYPE_IP ? "IP" :
		   "");
	seq_printf(m, " %d sessions, refcnt %d/%d\n", session_count,
		   tunnel->sock ? atomic_read(&tunnel->sock->sk_refcnt) : 0,
		   atomic_read(&tunnel->ref_count));

	seq_printf(m, " %08x rx %llu/%llu/%llu rx %llu/%llu/%llu\n",
		   tunnel->debug,
		   (unsigned long long)tunnel->stats.tx_packets,
		   (unsigned long long)tunnel->stats.tx_bytes,
		   (unsigned long long)tunnel->stats.tx_errors,
		   (unsigned long long)tunnel->stats.rx_packets,
		   (unsigned long long)tunnel->stats.rx_bytes,
		   (unsigned long long)tunnel->stats.rx_errors);

	if (tunnel->show != NULL)
		tunnel->show(m, tunnel);
}

static void capwap_dfs_seq_session_show(struct seq_file *m, void *v)
{
	struct capwap_session *session = v;

	seq_printf(m, "  SESSION %u, peer %u, %s\n", session->session_id,
		   session->peer_session_id,
		   session->pwtype == CAPWAP_PWTYPE_ETH ? "ETH" :
		   session->pwtype == CAPWAP_PWTYPE_PPP ? "PPP" :
		   "");
//	if (session->send_seq || session->recv_seq)
//		seq_printf(m, "   nr %hu, ns %hu\n", session->nr, session->ns);
	seq_printf(m, "   refcnt %d\n", atomic_read(&session->ref_count));
	seq_printf(m, "   config %d/%d/%08x %u\n",
		   session->mtu, session->mru,
//		   session->recv_seq ? 'R' : '-',
//		   session->send_seq ? 'S' : '-',
//		   session->data_seq == 1 ? "IPSEQ" :
//		   session->data_seq == 2 ? "DATASEQ" : "-",
		   session->lns_mode ? "LNS" : "LAC",
		   session->debug);
//		   jiffies_to_msecs(session->reorder_timeout));
//	seq_printf(m, "   offset %hu l2specific %hu/%hu\n",
//		   session->offset, session->l2specific_type, session->l2specific_len);
//	if (session->cookie_len) {
//		seq_printf(m, "   cookie %02x%02x%02x%02x",
//			   session->cookie[0], session->cookie[1],
//			   session->cookie[2], session->cookie[3]);
//		if (session->cookie_len == 8)
//			seq_printf(m, "%02x%02x%02x%02x",
//				   session->cookie[4], session->cookie[5],
//				   session->cookie[6], session->cookie[7]);
//		seq_printf(m, "\n");
//	}
//	if (session->peer_cookie_len) {
//		seq_printf(m, "   peer cookie %02x%02x%02x%02x",
//			   session->peer_cookie[0], session->peer_cookie[1],
//			   session->peer_cookie[2], session->peer_cookie[3]);
//		if (session->peer_cookie_len == 8)
//			seq_printf(m, "%02x%02x%02x%02x",
//				   session->peer_cookie[4], session->peer_cookie[5],
//				   session->peer_cookie[6], session->peer_cookie[7]);
//		seq_printf(m, "\n");
//	}

	seq_printf(m, "   tx %llu/%llu/%llu rx %llu/%llu/%llu\n",
//		   session->nr, session->ns,
		   (unsigned long long)session->stats.tx_packets,
		   (unsigned long long)session->stats.tx_bytes,
		   (unsigned long long)session->stats.tx_errors,
		   (unsigned long long)session->stats.rx_packets,
		   (unsigned long long)session->stats.rx_bytes,
		   (unsigned long long)session->stats.rx_errors);

	if (session->show != NULL)
		session->show(m, session);
}

static int capwap_dfs_seq_show(struct seq_file *m, void *v)
{
	struct capwap_dfs_seq_data *pd = v;

	/* display header on line 1 */
	if (v == SEQ_START_TOKEN) {
		seq_puts(m, "TUNNEL ID, peer ID from IP to IP\n");
		seq_puts(m, " CAPWAPv2/CAPWAPv3, UDP/IP\n");
		seq_puts(m, " sessions session-count, refcnt refcnt/sk->refcnt\n");
		seq_puts(m, " debug tx-pkts/bytes/errs rx-pkts/bytes/errs\n");
		seq_puts(m, "  SESSION ID, peer ID, PWTYPE\n");
		seq_puts(m, "   refcnt cnt\n");
		seq_puts(m, "   offset OFFSET l2specific TYPE/LEN\n");
//		seq_puts(m, "   [ cookie ]\n");
//		seq_puts(m, "   [ peer cookie ]\n");
		seq_puts(m, "   config mtu/mru/lns debug\n");
		seq_puts(m, "   nr/ns tx-pkts/bytes/errs rx-pkts/bytes/errs\n");
		goto out;
	}

	/* Show the tunnel or session context */
	if (pd->session == NULL)
		capwap_dfs_seq_tunnel_show(m, pd->tunnel);
	else
		capwap_dfs_seq_session_show(m, pd->session);

out:
	return 0;
}

static const struct seq_operations capwap_dfs_seq_ops = {
	.start		= capwap_dfs_seq_start,
	.next		= capwap_dfs_seq_next,
	.stop		= capwap_dfs_seq_stop,
	.show		= capwap_dfs_seq_show,
};

static int capwap_dfs_seq_open(struct inode *inode, struct file *file)
{
	struct capwap_dfs_seq_data *pd;
	struct seq_file *seq;
	int rc = -ENOMEM;

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (pd == NULL)
		goto out;

	/* Derive the network namespace from the pid opening the
	 * file.
	 */
	pd->net = get_net_ns_by_pid(current->pid);
	if (IS_ERR(pd->net)) {
		rc = PTR_ERR(pd->net);
		goto err_free_pd;
	}

	rc = seq_open(file, &capwap_dfs_seq_ops);
	if (rc)
		goto err_free_net;

	seq = file->private_data;
	seq->private = pd;

out:
	return rc;

err_free_net:
	put_net(pd->net);
err_free_pd:
	kfree(pd);
	goto out;
}

static int capwap_dfs_seq_release(struct inode *inode, struct file *file)
{
	struct capwap_dfs_seq_data *pd;
	struct seq_file *seq;

	seq = file->private_data;
	pd = seq->private;
	if (pd->net)
		put_net(pd->net);
	kfree(pd);
	seq_release(inode, file);

	return 0;
}

static const struct file_operations capwap_dfs_fops = {
	.owner		= THIS_MODULE,
	.open		= capwap_dfs_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= capwap_dfs_seq_release,
};

static int __init capwap_debugfs_init(void)
{
	int rc = 0;

	rootdir = debugfs_create_dir("capwap", NULL);
	if (IS_ERR(rootdir)) {
		rc = PTR_ERR(rootdir);
		rootdir = NULL;
		goto out;
	}

	tunnels = debugfs_create_file("tunnels", 0600, rootdir, NULL, &capwap_dfs_fops);
	if (tunnels == NULL)
		rc = -EIO;

	printk(KERN_INFO "CAPWAP debugfs support\n");

out:
	if (rc)
		printk(KERN_WARNING "capwap debugfs: unable to init\n");

	return rc;
}

static void __exit capwap_debugfs_exit(void)
{
	debugfs_remove(tunnels);
	debugfs_remove(rootdir);
}

module_init(capwap_debugfs_init);
module_exit(capwap_debugfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("James Chapman <jchapman@katalix.com>");
MODULE_DESCRIPTION("CAPWAP debugfs driver");
MODULE_VERSION("1.0");
