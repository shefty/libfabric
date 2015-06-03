/*
 * Copyright (c) 2015 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include "fi.h"
#include "fi_rbuf.h"
#include <rdma/fi_log.h>
#include "general.h"

enum gen_portal_state {
	GEN_PORTAL_IDLE,
	GEN_PORTAL_CONNECTING,
	GEN_PORTAL_ACTIVE,
	GEN_PORTAL_ERROR
};

struct gen_msg_buf {
	struct gen_portal *port;
	char		data[0];
};

struct gen_portal {
	struct fid_ep		*ep;
	struct gen_av		*av;

	enum gen_portal_state	state;

	struct gen_tx_cmd	*tx_cmd_head;
	struct gen_tx_cmd	*tx_pending_head;

	/* local TX mirrors remote RX */
	struct ringbuf		tx_bb;
	struct fid_mr		*tx_mr;
	struct ringbuf		rx_bb;
	struct fid_mr		*rx_mr;

	/* remote rx_bb */
	uint64_t		target_bb;
	uint64_t		target_key;

	struct gen_msg_buf	*msg_bufs;
	struct fid_mr		*msg_mr;

	//	union {
//		/* data stream */
//		struct {
//			unsigned int	  ctrl_seqno;
//			unsigned int	  ctrl_max_seqno;
//			uint16_t	  sseq_no;
//			uint16_t	  sseq_comp;
//			uint16_t	  rseq_no;
//			uint16_t	  rseq_comp;

//			int		  rbuf_msg_index;
//			int		  rbuf_bytes_avail;
//			int		  rbuf_free_offset;
//			int		  rbuf_offset;
//			struct ibv_mr	  *rmr;
//			uint8_t		  *rbuf;
//
//			int		  sbuf_bytes_avail;
//			struct ibv_mr	  *smr;
//			struct ibv_sge	  ssgl[2];
//		};
//	};
//
//	int		  sqe_avail;
//	uint32_t	  sbuf_size;
};

//#define RS_OLAP_START_SIZE 2048
//#define RS_MAX_TRANSFER 65536
//#define RS_SNDLOWAT 2048
//#define RS_QP_MIN_SIZE 16
//#define RS_QP_MAX_SIZE 0xFFFE
//#define RS_QP_CTRL_SIZE 4	/* must be power of 2 */
//#define RS_CONN_RETRIES 6
//#define RS_SGL_SIZE 2
//static struct index_map idm;
//static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
//
//enum {
//	RS_SVC_NOOP,
//	RS_SVC_ADD_DGRAM,
//	RS_SVC_REM_DGRAM,
//	RS_SVC_ADD_KEEPALIVE,
//	RS_SVC_REM_KEEPALIVE,
//	RS_SVC_MOD_KEEPALIVE
//};
//
//struct rs_svc_msg {
//	uint32_t cmd;
//	uint32_t status;
//	struct rsocket *rs;
//};
//
//struct rs_svc {
//	pthread_t id;
//	int sock[2];
//	int cnt;
//	int size;
//	int context_size;
//	void *(*run)(void *svc);
//	struct rsocket **rss;
//	void *contexts;
//};
//
//static struct pollfd *udp_svc_fds;
//static void *udp_svc_run(void *arg);
//static struct rs_svc udp_svc = {
//	.context_size = sizeof(*udp_svc_fds),
//	.run = udp_svc_run
//};
//static uint32_t *tcp_svc_timeouts;
//static void *tcp_svc_run(void *arg);
//static struct rs_svc tcp_svc = {
//	.context_size = sizeof(*tcp_svc_timeouts),
//	.run = tcp_svc_run
//};
//
//static uint16_t def_iomap_size = 0;
//static uint16_t def_inline = 64;
//static uint16_t def_sqsize = 384;
//static uint16_t def_rqsize = 384;
//static uint32_t def_mem = (1 << 17);
//static uint32_t def_wmem = (1 << 17);
//static uint32_t polling_time = 10;
//
///*
// * Immediate data format is determined by the upper bits
// * bit 31: message type, 0 - data, 1 - control
// * bit 30: buffers updated, 0 - target, 1 - direct-receive
// * bit 29: more data, 0 - end of transfer, 1 - more data available
// *
// * for data transfers:
// * bits [28:0]: bytes transferred
// * for control messages:
// * SGL, CTRL
// * bits [28-0]: receive credits granted
// * IOMAP_SGL
// * bits [28-16]: reserved, bits [15-0]: index
// */
//
//enum {
//	RS_OP_DATA,
//	RS_OP_RSVD_DATA_MORE,
//	RS_OP_WRITE, /* opcode is not transmitted over the network */
//	RS_OP_RSVD_DRA_MORE,
//	RS_OP_SGL,
//	RS_OP_RSVD,
//	RS_OP_IOMAP_SGL,
//	RS_OP_CTRL
//};
//#define rs_msg_set(op, data)  ((op << 29) | (uint32_t) (data))
//#define rs_msg_op(imm_data)   (imm_data >> 29)
//#define rs_msg_data(imm_data) (imm_data & 0x1FFFFFFF)
//#define RS_MSG_SIZE	      sizeof(uint32_t)
//
//#define RS_WR_ID_FLAG_RECV (((uint64_t) 1) << 63)
//#define RS_WR_ID_FLAG_MSG_SEND (((uint64_t) 1) << 62) /* See RS_OPT_MSG_SEND */
//#define rs_send_wr_id(data) ((uint64_t) data)
//#define rs_recv_wr_id(data) (RS_WR_ID_FLAG_RECV | (uint64_t) data)
//#define rs_wr_is_recv(wr_id) (wr_id & RS_WR_ID_FLAG_RECV)
//#define rs_wr_is_msg_send(wr_id) (wr_id & RS_WR_ID_FLAG_MSG_SEND)
//#define rs_wr_data(wr_id) ((uint32_t) wr_id)
//
//enum {
//	RS_CTRL_DISCONNECT,
//	RS_CTRL_KEEPALIVE,
//	RS_CTRL_SHUTDOWN
//};
//
//struct rs_msg {
//	uint32_t op;
//	uint32_t data;
//};
//struct rs_sge {
//	uint64_t addr;
//	uint32_t key;
//	uint32_t length;
//};

//
//#define RS_MAX_CTRL_MSG    (sizeof(struct rs_sge))
//#define rs_host_is_net()   (1 == htonl(1))
//#define RS_CONN_FLAG_NET   (1 << 0)
//#define RS_CONN_FLAG_IOMAP (1 << 1)
//
//struct rs_conn_data {
//	uint8_t		  version;
//	uint8_t		  flags;
//	uint16_t	  credits;
//	uint8_t		  reserved[3];
//	uint8_t		  target_iomap_size;
//	struct rs_sge	  target_sgl;
//	struct rs_sge	  data_buf;
//};
//
//struct rs_conn_private_data {
//	union {
//		struct rs_conn_data		conn_data;
//		struct {
//			struct ib_connect_hdr	ib_hdr;
//			struct rs_conn_data	conn_data;
//		} af_ib;
//	};
//};

//#define RS_OPT_SWAP_SGL   (1 << 0)
///*
// * iWarp does not support RDMA write with immediate data.  For iWarp, we
// * transfer rsocket messages as inline sends.
// */
//#define RS_OPT_MSG_SEND   (1 << 1)
//#define RS_OPT_SVC_ACTIVE (1 << 2)

//struct rsocket {
//	int		  type;
//	int		  index;
//	fastlock_t	  slock;
//	fastlock_t	  rlock;
//	fastlock_t	  cq_lock;
//	fastlock_t	  cq_wait_lock;
//	fastlock_t	  map_lock; /* acquire slock first if needed */
//
//	union {
//		/* data stream */
//		struct {
//			struct rdma_cm_id *cm_id;
//			uint64_t	  tcp_opts;
//			unsigned int	  keepalive_time;
//
//			unsigned int	  ctrl_seqno;
//			unsigned int	  ctrl_max_seqno;
//			uint16_t	  sseq_no;
//			uint16_t	  sseq_comp;
//			uint16_t	  rseq_no;
//			uint16_t	  rseq_comp;
//
//			int		  remote_sge;
//			struct rs_sge	  remote_sgl;
//			struct rs_sge	  remote_iomap;
//
//			struct ibv_mr	  *target_mr;
//			int		  target_sge;
//			int		  target_iomap_size;
//			void		  *target_buffer_list;
//			volatile struct rs_sge	  *target_sgl;
//			struct rs_iomap   *target_iomap;
//
//			int		  rbuf_msg_index;
//			int		  rbuf_bytes_avail;
//			int		  rbuf_free_offset;
//			int		  rbuf_offset;
//			struct ibv_mr	  *rmr;
//			uint8_t		  *rbuf;
//
//			int		  sbuf_bytes_avail;
//			struct ibv_mr	  *smr;
//			struct ibv_sge	  ssgl[2];
//		};
//	};
//
//	int		  retries;
//	int		  err;
//
//	int		  sqe_avail;
//	uint32_t	  sbuf_size;
//	uint16_t	  sq_size;
//	uint16_t	  sq_inline;
//
//	uint32_t	  rbuf_size;
//	uint16_t	  rq_size;
//	int		  rmsg_head;
//	int		  rmsg_tail;
//	union {
//		struct rs_msg	  *rmsg;
//		struct ds_rmsg	  *dmsg;
//	};
//
//	uint8_t		  *sbuf;
//	int		  unack_cqe;
//};

//static int rs_value_to_scale(int value, int bits)
//{
//	return value <= (1 << (bits - 1)) ?
//	       value : (1 << (bits - 1)) | (value >> bits);
//}
//
//static int rs_scale_to_value(int value, int bits)
//{
//	return value <= (1 << (bits - 1)) ?
//	       value : (value & ~(1 << (bits - 1))) << bits;
//}
//

//
///* We only inherit from listening sockets */
//static struct rsocket *rs_alloc(struct rsocket *inherited_rs, int type)
//{
//	struct rsocket *rs;
//
//	rs = calloc(1, sizeof *rs);
//	if (!rs)
//		return NULL;
//
//	rs->type = type;
//	rs->index = -1;
//	if (type == SOCK_DGRAM) {
//		rs->udp_sock = -1;
//		rs->epfd = -1;
//	}
//
//	if (inherited_rs) {
//		rs->sbuf_size = inherited_rs->sbuf_size;
//		rs->rbuf_size = inherited_rs->rbuf_size;
//		rs->sq_inline = inherited_rs->sq_inline;
//		rs->sq_size = inherited_rs->sq_size;
//		rs->rq_size = inherited_rs->rq_size;
//		if (type == SOCK_STREAM) {
//			rs->ctrl_max_seqno = inherited_rs->ctrl_max_seqno;
//			rs->target_iomap_size = inherited_rs->target_iomap_size;
//		}
//	} else {
//		rs->sbuf_size = def_wmem;
//		rs->rbuf_size = def_mem;
//		rs->sq_inline = def_inline;
//		rs->sq_size = def_sqsize;
//		rs->rq_size = def_rqsize;
//		if (type == SOCK_STREAM) {
//			rs->ctrl_max_seqno = RS_QP_CTRL_SIZE;
//			rs->target_iomap_size = def_iomap_size;
//		}
//	}
//	fastlock_init(&rs->slock);
//	fastlock_init(&rs->rlock);
//	fastlock_init(&rs->cq_lock);
//	fastlock_init(&rs->cq_wait_lock);
//	fastlock_init(&rs->map_lock);
//	dlist_init(&rs->iomap_list);
//	dlist_init(&rs->iomap_queue);
//	return rs;
//}
//

//
//static void rs_set_qp_size(struct rsocket *rs)
//{
//	uint16_t max_size;
//
//	max_size = min(ucma_max_qpsize(rs->cm_id), RS_QP_MAX_SIZE);
//
//	if (rs->sq_size > max_size)
//		rs->sq_size = max_size;
//	else if (rs->sq_size < RS_QP_MIN_SIZE)
//		rs->sq_size = RS_QP_MIN_SIZE;
//
//	if (rs->rq_size > max_size)
//		rs->rq_size = max_size;
//	else if (rs->rq_size < RS_QP_MIN_SIZE)
//		rs->rq_size = RS_QP_MIN_SIZE;
//}
//

//
//static int rs_init_bufs(struct rsocket *rs)
//{
//	uint32_t total_rbuf_size, total_sbuf_size;
//	size_t len;
//
//	rs->rmsg = calloc(rs->rq_size + 1, sizeof(*rs->rmsg));
//	if (!rs->rmsg)
//		return ERR(ENOMEM);
//
//	total_sbuf_size = rs->sbuf_size;
//	if (rs->sq_inline < RS_MAX_CTRL_MSG)
//		total_sbuf_size += RS_MAX_CTRL_MSG * RS_QP_CTRL_SIZE;
//	rs->sbuf = calloc(total_sbuf_size, 1);
//	if (!rs->sbuf)
//		return ERR(ENOMEM);
//
//	rs->smr = rdma_reg_msgs(rs->cm_id, rs->sbuf, total_sbuf_size);
//	if (!rs->smr)
//		return -1;
//
//	len = sizeof(*rs->target_sgl) * RS_SGL_SIZE +
//	      sizeof(*rs->target_iomap) * rs->target_iomap_size;
//	rs->target_buffer_list = malloc(len);
//	if (!rs->target_buffer_list)
//		return ERR(ENOMEM);
//
//	rs->target_mr = rdma_reg_write(rs->cm_id, rs->target_buffer_list, len);
//	if (!rs->target_mr)
//		return -1;
//
//	memset(rs->target_buffer_list, 0, len);
//	rs->target_sgl = rs->target_buffer_list;
//	if (rs->target_iomap_size)
//		rs->target_iomap = (struct rs_iomap *) (rs->target_sgl + RS_SGL_SIZE);
//
//	total_rbuf_size = rs->rbuf_size;
//	if (rs->opts & RS_OPT_MSG_SEND)
//		total_rbuf_size += rs->rq_size * RS_MSG_SIZE;
//	rs->rbuf = calloc(total_rbuf_size, 1);
//	if (!rs->rbuf)
//		return ERR(ENOMEM);
//
//	rs->rmr = rdma_reg_write(rs->cm_id, rs->rbuf, total_rbuf_size);
//	if (!rs->rmr)
//		return -1;
//
//	rs->ssgl[0].addr = rs->ssgl[1].addr = (uintptr_t) rs->sbuf;
//	rs->sbuf_bytes_avail = rs->sbuf_size;
//	rs->ssgl[0].lkey = rs->ssgl[1].lkey = rs->smr->lkey;
//
//	rs->rbuf_free_offset = rs->rbuf_size >> 1;
//	rs->rbuf_bytes_avail = rs->rbuf_size >> 1;
//	rs->sqe_avail = rs->sq_size - rs->ctrl_max_seqno;
//	rs->rseq_comp = rs->rq_size >> 1;
//	return 0;
//}
//

//
///*
// * If a user is waiting on a datagram rsocket through poll or select, then
// * we need the first completion to generate an event on the related epoll fd
// * in order to signal the user.  We arm the CQ on creation for this purpose
// */
//static int rs_create_cq(struct rsocket *rs, struct rdma_cm_id *cm_id)
//{
//	cm_id->recv_cq_channel = ibv_create_comp_channel(cm_id->verbs);
//	if (!cm_id->recv_cq_channel)
//		return -1;
//
//	cm_id->recv_cq = ibv_create_cq(cm_id->verbs, rs->sq_size + rs->rq_size,
//				       cm_id, cm_id->recv_cq_channel, 0);
//	if (!cm_id->recv_cq)
//		goto err1;
//
//	if (rs->fd_flags & O_NONBLOCK) {
//		if (fcntl(cm_id->recv_cq_channel->fd, F_SETFL, O_NONBLOCK))
//			goto err2;
//	}
//
//	ibv_req_notify_cq(cm_id->recv_cq, 0);
//	cm_id->send_cq_channel = cm_id->recv_cq_channel;
//	cm_id->send_cq = cm_id->recv_cq;
//	return 0;
//
//err2:
//	ibv_destroy_cq(cm_id->recv_cq);
//	cm_id->recv_cq = NULL;
//err1:
//	ibv_destroy_comp_channel(cm_id->recv_cq_channel);
//	cm_id->recv_cq_channel = NULL;
//	return -1;
//}
//
//static inline int rs_post_recv(struct rsocket *rs)
//{
//	struct ibv_recv_wr wr, *bad;
//	struct ibv_sge sge;
//
//	wr.next = NULL;
//	if (!(rs->opts & RS_OPT_MSG_SEND)) {
//		wr.wr_id = rs_recv_wr_id(0);
//		wr.sg_list = NULL;
//		wr.num_sge = 0;
//	} else {
//		wr.wr_id = rs_recv_wr_id(rs->rbuf_msg_index);
//		sge.addr = (uintptr_t) rs->rbuf + rs->rbuf_size +
//			   (rs->rbuf_msg_index * RS_MSG_SIZE);
//		sge.length = RS_MSG_SIZE;
//		sge.lkey = rs->rmr->lkey;
//
//		wr.sg_list = &sge;
//		wr.num_sge = 1;
//		if(++rs->rbuf_msg_index == rs->rq_size)
//			rs->rbuf_msg_index = 0;
//	}
//
//	return rdma_seterrno(ibv_post_recv(rs->cm_id->qp, &wr, &bad));
//}
//

//
//static int rs_create_ep(struct rsocket *rs)
//{
//	struct ibv_qp_init_attr qp_attr;
//	int i, ret;
//
//	rs_set_qp_size(rs);
//	if (rs->cm_id->verbs->device->transport_type == IBV_TRANSPORT_IWARP)
//		rs->opts |= RS_OPT_MSG_SEND;
//	ret = rs_create_cq(rs, rs->cm_id);
//	if (ret)
//		return ret;
//
//	memset(&qp_attr, 0, sizeof qp_attr);
//	qp_attr.qp_context = rs;
//	qp_attr.send_cq = rs->cm_id->send_cq;
//	qp_attr.recv_cq = rs->cm_id->recv_cq;
//	qp_attr.qp_type = IBV_QPT_RC;
//	qp_attr.sq_sig_all = 1;
//	qp_attr.cap.max_send_wr = rs->sq_size;
//	qp_attr.cap.max_recv_wr = rs->rq_size;
//	qp_attr.cap.max_send_sge = 2;
//	qp_attr.cap.max_recv_sge = 1;
//	qp_attr.cap.max_inline_data = rs->sq_inline;
//
//	ret = rdma_create_qp(rs->cm_id, NULL, &qp_attr);
//	if (ret)
//		return ret;
//
//	rs->sq_inline = qp_attr.cap.max_inline_data;
//	if ((rs->opts & RS_OPT_MSG_SEND) && (rs->sq_inline < RS_MSG_SIZE))
//		return ERR(ENOTSUP);
//
//	ret = rs_init_bufs(rs);
//	if (ret)
//		return ret;
//
//	for (i = 0; i < rs->rq_size; i++) {
//		ret = rs_post_recv(rs);
//		if (ret)
//			return ret;
//	}
//	return 0;
//}

//static void rs_free(struct rsocket *rs)
//{
//	if (rs->type == SOCK_DGRAM) {
//		ds_free(rs);
//		return;
//	}
//
//	if (rs->rmsg)
//		free(rs->rmsg);
//
//	if (rs->sbuf) {
//		if (rs->smr)
//			rdma_dereg_mr(rs->smr);
//		free(rs->sbuf);
//	}
//
//	if (rs->rbuf) {
//		if (rs->rmr)
//			rdma_dereg_mr(rs->rmr);
//		free(rs->rbuf);
//	}
//
//	if (rs->target_buffer_list) {
//		if (rs->target_mr)
//			rdma_dereg_mr(rs->target_mr);
//		free(rs->target_buffer_list);
//	}
//
//	if (rs->cm_id) {
//		rs_free_iomappings(rs);
//		if (rs->cm_id->qp) {
//			ibv_ack_cq_events(rs->cm_id->recv_cq, rs->unack_cqe);
//			rdma_destroy_qp(rs->cm_id);
//		}
//		rdma_destroy_id(rs->cm_id);
//	}
//
//	if (rs->index >= 0)
//		rs_remove(rs);
//
//	fastlock_destroy(&rs->map_lock);
//	fastlock_destroy(&rs->cq_wait_lock);
//	fastlock_destroy(&rs->cq_lock);
//	fastlock_destroy(&rs->rlock);
//	fastlock_destroy(&rs->slock);
//	free(rs);
//}
//
//static size_t rs_conn_data_offset(struct rsocket *rs)
//{
//	return (rs->cm_id->route.addr.src_addr.sa_family == AF_IB) ?
//		sizeof(struct ib_connect_hdr) : 0;
//}
//
//static void rs_format_conn_data(struct rsocket *rs, struct rs_conn_data *conn)
//{
//	conn->version = 1;
//	conn->flags = RS_CONN_FLAG_IOMAP |
//		      (rs_host_is_net() ? RS_CONN_FLAG_NET : 0);
//	conn->credits = htons(rs->rq_size);
//	memset(conn->reserved, 0, sizeof conn->reserved);
//	conn->target_iomap_size = (uint8_t) rs_value_to_scale(rs->target_iomap_size, 8);
//
//	conn->target_sgl.addr = htonll((uintptr_t) rs->target_sgl);
//	conn->target_sgl.length = htonl(RS_SGL_SIZE);
//	conn->target_sgl.key = htonl(rs->target_mr->rkey);
//
//	conn->data_buf.addr = htonll((uintptr_t) rs->rbuf);
//	conn->data_buf.length = htonl(rs->rbuf_size >> 1);
//	conn->data_buf.key = htonl(rs->rmr->rkey);
//}
//
//static void rs_save_conn_data(struct rsocket *rs, struct rs_conn_data *conn)
//{
//	rs->remote_sgl.addr = ntohll(conn->target_sgl.addr);
//	rs->remote_sgl.length = ntohl(conn->target_sgl.length);
//	rs->remote_sgl.key = ntohl(conn->target_sgl.key);
//	rs->remote_sge = 1;
//	if ((rs_host_is_net() && !(conn->flags & RS_CONN_FLAG_NET)) ||
//	    (!rs_host_is_net() && (conn->flags & RS_CONN_FLAG_NET)))
//		rs->opts = RS_OPT_SWAP_SGL;
//
//	if (conn->flags & RS_CONN_FLAG_IOMAP) {
//		rs->remote_iomap.addr = rs->remote_sgl.addr +
//					sizeof(rs->remote_sgl) * rs->remote_sgl.length;
//		rs->remote_iomap.length = rs_scale_to_value(conn->target_iomap_size, 8);
//		rs->remote_iomap.key = rs->remote_sgl.key;
//	}
//
//	rs->target_sgl[0].addr = ntohll(conn->data_buf.addr);
//	rs->target_sgl[0].length = ntohl(conn->data_buf.length);
//	rs->target_sgl[0].key = ntohl(conn->data_buf.key);
//
//	rs->sseq_comp = ntohs(conn->credits);
//}

//
//int rsocket(int domain, int type, int protocol)
//{
//	struct rsocket *rs;
//	int index, ret;
//
//	if ((domain != AF_INET && domain != AF_INET6 && domain != AF_IB) ||
//	    ((type != SOCK_STREAM) && (type != SOCK_DGRAM)) ||
//	    (type == SOCK_STREAM && protocol && protocol != IPPROTO_TCP) ||
//	    (type == SOCK_DGRAM && protocol && protocol != IPPROTO_UDP))
//		return ERR(ENOTSUP);
//
//	rs_configure();
//	rs = rs_alloc(NULL, type);
//	if (!rs)
//		return ERR(ENOMEM);
//
//	if (type == SOCK_STREAM) {
//		ret = rdma_create_id(NULL, &rs->cm_id, rs, RDMA_PS_TCP);
//		if (ret)
//			goto err;
//
//		rs->cm_id->route.addr.src_addr.sa_family = domain;
//		index = rs->cm_id->channel->fd;
//	} else {
//		ret = ds_init(rs, domain);
//		if (ret)
//			goto err;
//
//		index = rs->udp_sock;
//	}
//
//	ret = rs_insert(rs, index);
//	if (ret < 0)
//		goto err;
//
//	return rs->index;
//
//err:
//	rs_free(rs);
//	return ret;
//}

///*
// * Nonblocking is usually not inherited between sockets, but we need to
// * inherit it here to establish the connection only.  This is needed to
// * prevent rdma_accept from blocking until the remote side finishes
// * establishing the connection.  If we were to allow rdma_accept to block,
// * then a single thread cannot establish a connection with itself, or
// * two threads which try to connect to each other can deadlock trying to
// * form a connection.
// *
// * Data transfers on the new socket remain blocking unless the user
// * specifies otherwise through rfcntl.
// */
//int raccept(int socket, struct sockaddr *addr, socklen_t *addrlen)
//{
//	struct rsocket *rs, *new_rs;
//	struct rdma_conn_param param;
//	struct rs_conn_data *creq, cresp;
//	int ret;
//
//	rs = idm_lookup(&idm, socket);
//	if (!rs)
//		return ERR(EBADF);
//	new_rs = rs_alloc(rs, rs->type);
//	if (!new_rs)
//		return ERR(ENOMEM);
//
//	ret = rdma_get_request(rs->cm_id, &new_rs->cm_id);
//	if (ret)
//		goto err;
//
//	ret = rs_insert(new_rs, new_rs->cm_id->channel->fd);
//	if (ret < 0)
//		goto err;
//
//	creq = (struct rs_conn_data *)
//	       (new_rs->cm_id->event->param.conn.private_data + rs_conn_data_offset(rs));
//	if (creq->version != 1) {
//		ret = ERR(ENOTSUP);
//		goto err;
//	}
//
//	if (rs->fd_flags & O_NONBLOCK)
//		fcntl(new_rs->cm_id->channel->fd, F_SETFL, O_NONBLOCK);
//
//	ret = rs_create_ep(new_rs);
//	if (ret)
//		goto err;
//
//	rs_save_conn_data(new_rs, creq);
//	param = new_rs->cm_id->event->param.conn;
//	rs_format_conn_data(new_rs, &cresp);
//	param.private_data = &cresp;
//	param.private_data_len = sizeof cresp;
//	ret = rdma_accept(new_rs->cm_id, &param);
//	if (!ret)
//		new_rs->state = rs_connect_rdwr;
//	else if (errno == EAGAIN || errno == EWOULDBLOCK)
//		new_rs->state = rs_accepting;
//	else
//		goto err;
//
//	if (addr && addrlen)
//		rgetpeername(new_rs->index, addr, addrlen);
//	return new_rs->index;
//
//err:
//	rs_free(new_rs);
//	return ret;
//}




//int rconnect(int socket, const struct sockaddr *addr, socklen_t addrlen)
//{
//	struct rsocket *rs;
//	int ret;
//
//	rs = idm_lookup(&idm, socket);
//	if (!rs)
//		return ERR(EBADF);
//	if (rs->type == SOCK_STREAM) {
//		memcpy(&rs->cm_id->route.addr.dst_addr, addr, addrlen);
//		ret = rs_do_connect(rs);
//	} else {
//		if (rs->state == rs_init) {
//			ret = ds_init_ep(rs);
//			if (ret)
//				return ret;
//		}
//
//		fastlock_acquire(&rs->slock);
//		ret = connect(rs->udp_sock, addr, addrlen);
//		if (!ret)
//			ret = ds_get_dest(rs, addr, addrlen, &rs->conn_dest);
//		fastlock_release(&rs->slock);
//	}
//	return ret;
//}
//
//static void *rs_get_ctrl_buf(struct rsocket *rs)
//{
//	return rs->sbuf + rs->sbuf_size +
//		RS_MAX_CTRL_MSG * (rs->ctrl_seqno & (RS_QP_CTRL_SIZE - 1));
//}
//
//static int rs_post_msg(struct rsocket *rs, uint32_t msg)
//{
//	struct ibv_send_wr wr, *bad;
//	struct ibv_sge sge;
//
//	wr.wr_id = rs_send_wr_id(msg);
//	wr.next = NULL;
//	if (!(rs->opts & RS_OPT_MSG_SEND)) {
//		wr.sg_list = NULL;
//		wr.num_sge = 0;
//		wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
//		wr.send_flags = 0;
//		wr.imm_data = htonl(msg);
//	} else {
//		sge.addr = (uintptr_t) &msg;
//		sge.lkey = 0;
//		sge.length = sizeof msg;
//		wr.sg_list = &sge;
//		wr.num_sge = 1;
//		wr.opcode = IBV_WR_SEND;
//		wr.send_flags = IBV_SEND_INLINE;
//	}
//
//	return rdma_seterrno(ibv_post_send(rs->cm_id->qp, &wr, &bad));
//}
//
//static int rs_post_write(struct rsocket *rs,
//			 struct ibv_sge *sgl, int nsge,
//			 uint32_t wr_data, int flags,
//			 uint64_t addr, uint32_t rkey)
//{
//	struct ibv_send_wr wr, *bad;
//
//	wr.wr_id = rs_send_wr_id(wr_data);
//	wr.next = NULL;
//	wr.sg_list = sgl;
//	wr.num_sge = nsge;
//	wr.opcode = IBV_WR_RDMA_WRITE;
//	wr.send_flags = flags;
//	wr.wr.rdma.remote_addr = addr;
//	wr.wr.rdma.rkey = rkey;
//
//	return rdma_seterrno(ibv_post_send(rs->cm_id->qp, &wr, &bad));
//}
//
//static int rs_post_write_msg(struct rsocket *rs,
//			 struct ibv_sge *sgl, int nsge,
//			 uint32_t msg, int flags,
//			 uint64_t addr, uint32_t rkey)
//{
//	struct ibv_send_wr wr, *bad;
//	struct ibv_sge sge;
//	int ret;
//
//	wr.next = NULL;
//	if (!(rs->opts & RS_OPT_MSG_SEND)) {
//		wr.wr_id = rs_send_wr_id(msg);
//		wr.sg_list = sgl;
//		wr.num_sge = nsge;
//		wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
//		wr.send_flags = flags;
//		wr.imm_data = htonl(msg);
//		wr.wr.rdma.remote_addr = addr;
//		wr.wr.rdma.rkey = rkey;
//
//		return rdma_seterrno(ibv_post_send(rs->cm_id->qp, &wr, &bad));
//	} else {
//		ret = rs_post_write(rs, sgl, nsge, msg, flags, addr, rkey);
//		if (!ret) {
//			wr.wr_id = rs_send_wr_id(rs_msg_set(rs_msg_op(msg), 0)) |
//				   RS_WR_ID_FLAG_MSG_SEND;
//			sge.addr = (uintptr_t) &msg;
//			sge.lkey = 0;
//			sge.length = sizeof msg;
//			wr.sg_list = &sge;
//			wr.num_sge = 1;
//			wr.opcode = IBV_WR_SEND;
//			wr.send_flags = IBV_SEND_INLINE;
//
//			ret = rdma_seterrno(ibv_post_send(rs->cm_id->qp, &wr, &bad));
//		}
//		return ret;
//	}
//}

//static uint32_t rs_sbuf_left(struct rsocket *rs)
//{
//	return (uint32_t) (((uint64_t) (uintptr_t) &rs->sbuf[rs->sbuf_size]) -
//			   rs->ssgl[0].addr);
//}
//
//static void rs_send_credits(struct rsocket *rs)
//{
//	struct ibv_sge ibsge;
//	struct rs_sge sge, *sge_buf;
//	int flags;
//
//	rs->ctrl_seqno++;
//	rs->rseq_comp = rs->rseq_no + (rs->rq_size >> 1);
//	if (rs->rbuf_bytes_avail >= (rs->rbuf_size >> 1)) {
//		if (rs->opts & RS_OPT_MSG_SEND)
//			rs->ctrl_seqno++;
//
//		if (!(rs->opts & RS_OPT_SWAP_SGL)) {
//			sge.addr = (uintptr_t) &rs->rbuf[rs->rbuf_free_offset];
//			sge.key = rs->rmr->rkey;
//			sge.length = rs->rbuf_size >> 1;
//		} else {
//			sge.addr = bswap_64((uintptr_t) &rs->rbuf[rs->rbuf_free_offset]);
//			sge.key = bswap_32(rs->rmr->rkey);
//			sge.length = bswap_32(rs->rbuf_size >> 1);
//		}
//
//		if (rs->sq_inline < sizeof sge) {
//			sge_buf = rs_get_ctrl_buf(rs);
//			memcpy(sge_buf, &sge, sizeof sge);
//			ibsge.addr = (uintptr_t) sge_buf;
//			ibsge.lkey = rs->smr->lkey;
//			flags = 0;
//		} else {
//			ibsge.addr = (uintptr_t) &sge;
//			ibsge.lkey = 0;
//			flags = IBV_SEND_INLINE;
//		}
//		ibsge.length = sizeof(sge);
//
//		rs_post_write_msg(rs, &ibsge, 1,
//			rs_msg_set(RS_OP_SGL, rs->rseq_no + rs->rq_size), flags,
//			rs->remote_sgl.addr + rs->remote_sge * sizeof(struct rs_sge),
//			rs->remote_sgl.key);
//
//		rs->rbuf_bytes_avail -= rs->rbuf_size >> 1;
//		rs->rbuf_free_offset += rs->rbuf_size >> 1;
//		if (rs->rbuf_free_offset >= rs->rbuf_size)
//			rs->rbuf_free_offset = 0;
//		if (++rs->remote_sge == rs->remote_sgl.length)
//			rs->remote_sge = 0;
//	} else {
//		rs_post_msg(rs, rs_msg_set(RS_OP_SGL, rs->rseq_no + rs->rq_size));
//	}
//}
//
//static inline int rs_ctrl_avail(struct rsocket *rs)
//{
//	return rs->ctrl_seqno != rs->ctrl_max_seqno;
//}
//
///* Protocols that do not support RDMA write with immediate may require 2 msgs */
//static inline int rs_2ctrl_avail(struct rsocket *rs)
//{
//	return (int)((rs->ctrl_seqno + 1) - rs->ctrl_max_seqno) < 0;
//}
//
//static int rs_give_credits(struct rsocket *rs)
//{
//	if (!(rs->opts & RS_OPT_MSG_SEND)) {
//		return ((rs->rbuf_bytes_avail >= (rs->rbuf_size >> 1)) ||
//			((short) ((short) rs->rseq_no - (short) rs->rseq_comp) >= 0)) &&
//		       rs_ctrl_avail(rs) && (rs->state & rs_connected);
//	} else {
//		return ((rs->rbuf_bytes_avail >= (rs->rbuf_size >> 1)) ||
//			((short) ((short) rs->rseq_no - (short) rs->rseq_comp) >= 0)) &&
//		       rs_2ctrl_avail(rs) && (rs->state & rs_connected);
//	}
//}
//
//static void rs_update_credits(struct rsocket *rs)
//{
//	if (rs_give_credits(rs))
//		rs_send_credits(rs);
//}
//
//static int rs_poll_cq(struct rsocket *rs)
//{
//	struct ibv_wc wc;
//	uint32_t msg;
//	int ret, rcnt = 0;
//
//	while ((ret = ibv_poll_cq(rs->cm_id->recv_cq, 1, &wc)) > 0) {
//		if (rs_wr_is_recv(wc.wr_id)) {
//			if (wc.status != IBV_WC_SUCCESS)
//				continue;
//			rcnt++;
//
//			if (wc.wc_flags & IBV_WC_WITH_IMM) {
//				msg = ntohl(wc.imm_data);
//			} else {
//				msg = ((uint32_t *) (rs->rbuf + rs->rbuf_size))
//					[rs_wr_data(wc.wr_id)];
//
//			}
//			switch (rs_msg_op(msg)) {
//			case RS_OP_SGL:
//				rs->sseq_comp = (uint16_t) rs_msg_data(msg);
//				break;
//			case RS_OP_IOMAP_SGL:
//				/* The iomap was updated, that's nice to know. */
//				break;
//			case RS_OP_CTRL:
//				if (rs_msg_data(msg) == RS_CTRL_DISCONNECT) {
//					rs->state = rs_disconnected;
//					return 0;
//				} else if (rs_msg_data(msg) == RS_CTRL_SHUTDOWN) {
//					if (rs->state & rs_writable) {
//						rs->state &= ~rs_readable;
//					} else {
//						rs->state = rs_disconnected;
//						return 0;
//					}
//				}
//				break;
//			case RS_OP_WRITE:
//				/* We really shouldn't be here. */
//				break;
//			default:
//				rs->rmsg[rs->rmsg_tail].op = rs_msg_op(msg);
//				rs->rmsg[rs->rmsg_tail].data = rs_msg_data(msg);
//				if (++rs->rmsg_tail == rs->rq_size + 1)
//					rs->rmsg_tail = 0;
//				break;
//			}
//		} else {
//			switch  (rs_msg_op(rs_wr_data(wc.wr_id))) {
//			case RS_OP_SGL:
//				rs->ctrl_max_seqno++;
//				break;
//			case RS_OP_CTRL:
//				rs->ctrl_max_seqno++;
//				if (rs_msg_data(rs_wr_data(wc.wr_id)) == RS_CTRL_DISCONNECT)
//					rs->state = rs_disconnected;
//				break;
//			case RS_OP_IOMAP_SGL:
//				rs->sqe_avail++;
//				if (!rs_wr_is_msg_send(wc.wr_id))
//					rs->sbuf_bytes_avail += sizeof(struct rs_iomap);
//				break;
//			default:
//				rs->sqe_avail++;
//				rs->sbuf_bytes_avail += rs_msg_data(rs_wr_data(wc.wr_id));
//				break;
//			}
//			if (wc.status != IBV_WC_SUCCESS && (rs->state & rs_connected)) {
//				rs->state = rs_error;
//				rs->err = EIO;
//			}
//		}
//	}
//
//	if (rs->state & rs_connected) {
//		while (!ret && rcnt--)
//			ret = rs_post_recv(rs);
//
//		if (ret) {
//			rs->state = rs_error;
//			rs->err = errno;
//		}
//	}
//	return ret;
//}
//
//static int rs_get_cq_event(struct rsocket *rs)
//{
//	struct ibv_cq *cq;
//	void *context;
//	int ret;
//
//	if (!rs->cq_armed)
//		return 0;
//
//	ret = ibv_get_cq_event(rs->cm_id->recv_cq_channel, &cq, &context);
//	if (!ret) {
//		if (++rs->unack_cqe >= rs->sq_size + rs->rq_size) {
//			ibv_ack_cq_events(rs->cm_id->recv_cq, rs->unack_cqe);
//			rs->unack_cqe = 0;
//		}
//		rs->cq_armed = 0;
//	} else if (!(errno == EAGAIN || errno == EINTR)) {
//		rs->state = rs_error;
//	}
//
//	return ret;
//}
//
///*
// * Although we serialize rsend and rrecv calls with respect to themselves,
// * both calls may run simultaneously and need to poll the CQ for completions.
// * We need to serialize access to the CQ, but rsend and rrecv need to
// * allow each other to make forward progress.
// *
// * For example, rsend may need to wait for credits from the remote side,
// * which could be stalled until the remote process calls rrecv.  This should
// * not block rrecv from receiving data from the remote side however.
// *
// * We handle this by using two locks.  The cq_lock protects against polling
// * the CQ and processing completions.  The cq_wait_lock serializes access to
// * waiting on the CQ.
// */
//static int rs_process_cq(struct rsocket *rs, int nonblock, int (*test)(struct rsocket *rs))
//{
//	int ret;
//
//	fastlock_acquire(&rs->cq_lock);
//	do {
//		rs_update_credits(rs);
//		ret = rs_poll_cq(rs);
//		if (test(rs)) {
//			ret = 0;
//			break;
//		} else if (ret) {
//			break;
//		} else if (nonblock) {
//			ret = ERR(EWOULDBLOCK);
//		} else if (!rs->cq_armed) {
//			ibv_req_notify_cq(rs->cm_id->recv_cq, 0);
//			rs->cq_armed = 1;
//		} else {
//			rs_update_credits(rs);
//			fastlock_acquire(&rs->cq_wait_lock);
//			fastlock_release(&rs->cq_lock);
//
//			ret = rs_get_cq_event(rs);
//			fastlock_release(&rs->cq_wait_lock);
//			fastlock_acquire(&rs->cq_lock);
//		}
//	} while (!ret);
//
//	rs_update_credits(rs);
//	fastlock_release(&rs->cq_lock);
//	return ret;
//}
//
//static int rs_get_comp(struct rsocket *rs, int nonblock, int (*test)(struct rsocket *rs))
//{
//	struct timeval s, e;
//	uint32_t poll_time = 0;
//	int ret;
//
//	do {
//		ret = rs_process_cq(rs, 1, test);
//		if (!ret || nonblock || errno != EWOULDBLOCK)
//			return ret;
//
//		if (!poll_time)
//			gettimeofday(&s, NULL);
//
//		gettimeofday(&e, NULL);
//		poll_time = (e.tv_sec - s.tv_sec) * 1000000 +
//			    (e.tv_usec - s.tv_usec) + 1;
//	} while (poll_time <= polling_time);
//
//	ret = rs_process_cq(rs, 0, test);
//	return ret;
//}
//

//
//static int rs_nonblocking(struct rsocket *rs, int flags)
//{
//	return (rs->fd_flags & O_NONBLOCK) || (flags & MSG_DONTWAIT);
//}

//
///*
// * We use hardware flow control to prevent over running the remote
// * receive queue.  However, data transfers still require space in
// * the remote rmsg queue, or we risk losing notification that data
// * has been transfered.
// *
// * Be careful with race conditions in the check below.  The target SGL
// * may be updated by a remote RDMA write.
// */
//static int rs_can_send(struct rsocket *rs)
//{
//	if (!(rs->opts & RS_OPT_MSG_SEND)) {
//		return rs->sqe_avail && (rs->sbuf_bytes_avail >= RS_SNDLOWAT) &&
//		       (rs->sseq_no != rs->sseq_comp) &&
//		       (rs->target_sgl[rs->target_sge].length != 0);
//	} else {
//		return (rs->sqe_avail >= 2) && (rs->sbuf_bytes_avail >= RS_SNDLOWAT) &&
//		       (rs->sseq_no != rs->sseq_comp) &&
//		       (rs->target_sgl[rs->target_sge].length != 0);
//	}
//}
//
//static int rs_conn_can_send(struct rsocket *rs)
//{
//	return rs_can_send(rs) || !(rs->state & rs_writable);
//}
//
//static int rs_conn_can_send_ctrl(struct rsocket *rs)
//{
//	return rs_ctrl_avail(rs) || !(rs->state & rs_connected);
//}
//
//static int rs_have_rdata(struct rsocket *rs)
//{
//	return (rs->rmsg_head != rs->rmsg_tail);
//}
//
//static int rs_conn_have_rdata(struct rsocket *rs)
//{
//	return rs_have_rdata(rs) || !(rs->state & rs_readable);
//}
//
//static int rs_conn_all_sends_done(struct rsocket *rs)
//{
//	return ((((int) rs->ctrl_max_seqno) - ((int) rs->ctrl_seqno)) +
//		rs->sqe_avail == rs->sq_size) ||
//	       !(rs->state & rs_connected);
//}

//
///*
// * Continue to receive any queued data even if the remote side has disconnected.
// */
//ssize_t rrecv(int socket, void *buf, size_t len, int flags)
//{
//	struct rsocket *rs;
//	size_t left = len;
//	uint32_t end_size, rsize;
//	int ret = 0;
//
//	rs = idm_at(&idm, socket);
//	if (rs->type == SOCK_DGRAM) {
//		fastlock_acquire(&rs->rlock);
//		ret = ds_recvfrom(rs, buf, len, flags, NULL, 0);
//		fastlock_release(&rs->rlock);
//		return ret;
//	}
//
//	if (rs->state & rs_opening) {
//		ret = rs_do_connect(rs);
//		if (ret) {
//			if (errno == EINPROGRESS)
//				errno = EAGAIN;
//			return ret;
//		}
//	}
//	fastlock_acquire(&rs->rlock);
//	do {
//		if (!rs_have_rdata(rs)) {
//			ret = rs_get_comp(rs, rs_nonblocking(rs, flags),
//					  rs_conn_have_rdata);
//			if (ret)
//				break;
//		}
//
//		if (flags & MSG_PEEK) {
//			left = len - rs_peek(rs, buf, left);
//			break;
//		}
//
//		for (; left && rs_have_rdata(rs); left -= rsize) {
//			if (left < rs->rmsg[rs->rmsg_head].data) {
//				rsize = left;
//				rs->rmsg[rs->rmsg_head].data -= left;
//			} else {
//				rs->rseq_no++;
//				rsize = rs->rmsg[rs->rmsg_head].data;
//				if (++rs->rmsg_head == rs->rq_size + 1)
//					rs->rmsg_head = 0;
//			}
//
//			end_size = rs->rbuf_size - rs->rbuf_offset;
//			if (rsize > end_size) {
//				memcpy(buf, &rs->rbuf[rs->rbuf_offset], end_size);
//				rs->rbuf_offset = 0;
//				buf += end_size;
//				rsize -= end_size;
//				left -= end_size;
//				rs->rbuf_bytes_avail += end_size;
//			}
//			memcpy(buf, &rs->rbuf[rs->rbuf_offset], rsize);
//			rs->rbuf_offset += rsize;
//			buf += rsize;
//			rs->rbuf_bytes_avail += rsize;
//		}
//
//	} while (left && (flags & MSG_WAITALL) && (rs->state & rs_readable));
//
//	fastlock_release(&rs->rlock);
//	return (ret && left == len) ? ret : len - left;
//}


//
///*
// * We overlap sending the data, by posting a small work request immediately,
// * then increasing the size of the send on each iteration.
// */
//ssize_t rsend(int socket, const void *buf, size_t len, int flags)
//{
//	struct rsocket *rs;
//	struct ibv_sge sge;
//	size_t left = len;
//	uint32_t xfer_size, olen = RS_OLAP_START_SIZE;
//	int ret = 0;
//
//	rs = idm_at(&idm, socket);
//	if (rs->type == SOCK_DGRAM) {
//		fastlock_acquire(&rs->slock);
//		ret = dsend(rs, buf, len, flags);
//		fastlock_release(&rs->slock);
//		return ret;
//	}
//
//	if (rs->state & rs_opening) {
//		ret = rs_do_connect(rs);
//		if (ret) {
//			if (errno == EINPROGRESS)
//				errno = EAGAIN;
//			return ret;
//		}
//	}
//
//	fastlock_acquire(&rs->slock);
//	if (rs->iomap_pending) {
//		ret = rs_send_iomaps(rs, flags);
//		if (ret)
//			goto out;
//	}
//	for (; left; left -= xfer_size, buf += xfer_size) {
//		if (!rs_can_send(rs)) {
//			ret = rs_get_comp(rs, rs_nonblocking(rs, flags),
//					  rs_conn_can_send);
//			if (ret)
//				break;
//			if (!(rs->state & rs_writable)) {
//				ret = ERR(ECONNRESET);
//				break;
//			}
//		}
//
//		if (olen < left) {
//			xfer_size = olen;
//			if (olen < RS_MAX_TRANSFER)
//				olen <<= 1;
//		} else {
//			xfer_size = left;
//		}
//
//		if (xfer_size > rs->sbuf_bytes_avail)
//			xfer_size = rs->sbuf_bytes_avail;
//		if (xfer_size > rs->target_sgl[rs->target_sge].length)
//			xfer_size = rs->target_sgl[rs->target_sge].length;
//
//		if (xfer_size <= rs->sq_inline) {
//			sge.addr = (uintptr_t) buf;
//			sge.length = xfer_size;
//			sge.lkey = 0;
//			ret = rs_write_data(rs, &sge, 1, xfer_size, IBV_SEND_INLINE);
//		} else if (xfer_size <= rs_sbuf_left(rs)) {
//			memcpy((void *) (uintptr_t) rs->ssgl[0].addr, buf, xfer_size);
//			rs->ssgl[0].length = xfer_size;
//			ret = rs_write_data(rs, rs->ssgl, 1, xfer_size, 0);
//			if (xfer_size < rs_sbuf_left(rs))
//				rs->ssgl[0].addr += xfer_size;
//			else
//				rs->ssgl[0].addr = (uintptr_t) rs->sbuf;
//		} else {
//			rs->ssgl[0].length = rs_sbuf_left(rs);
//			memcpy((void *) (uintptr_t) rs->ssgl[0].addr, buf,
//				rs->ssgl[0].length);
//			rs->ssgl[1].length = xfer_size - rs->ssgl[0].length;
//			memcpy(rs->sbuf, buf + rs->ssgl[0].length, rs->ssgl[1].length);
//			ret = rs_write_data(rs, rs->ssgl, 2, xfer_size, 0);
//			rs->ssgl[0].addr = (uintptr_t) rs->sbuf + rs->ssgl[1].length;
//		}
//		if (ret)
//			break;
//	}
//out:
//	fastlock_release(&rs->slock);
//
//	return (ret && left == len) ? ret : len - left;
//}



///*
// * For graceful disconnect, notify the remote side that we're
// * disconnecting and wait until all outstanding sends complete, provided
// * that the remote side has not sent a disconnect message.
// */
//int rshutdown(int socket, int how)
//{
//	struct rsocket *rs;
//	int ctrl, ret = 0;
//
//	rs = idm_lookup(&idm, socket);
//	if (!rs)
//		return ERR(EBADF);
//	if (rs->opts & RS_OPT_SVC_ACTIVE)
//		rs_notify_svc(&tcp_svc, rs, RS_SVC_REM_KEEPALIVE);
//
//	if (rs->fd_flags & O_NONBLOCK)
//		rs_set_nonblocking(rs, 0);
//
//	if (rs->state & rs_connected) {
//		if (how == SHUT_RDWR) {
//			ctrl = RS_CTRL_DISCONNECT;
//			rs->state &= ~(rs_readable | rs_writable);
//		} else if (how == SHUT_WR) {
//			rs->state &= ~rs_writable;
//			ctrl = (rs->state & rs_readable) ?
//				RS_CTRL_SHUTDOWN : RS_CTRL_DISCONNECT;
//		} else {
//			rs->state &= ~rs_readable;
//			if (rs->state & rs_writable)
//				goto out;
//			ctrl = RS_CTRL_DISCONNECT;
//		}
//		if (!rs_ctrl_avail(rs)) {
//			ret = rs_process_cq(rs, 0, rs_conn_can_send_ctrl);
//			if (ret)
//				goto out;
//		}
//
//		if ((rs->state & rs_connected) && rs_ctrl_avail(rs)) {
//			rs->ctrl_seqno++;
//			ret = rs_post_msg(rs, rs_msg_set(RS_OP_CTRL, ctrl));
//		}
//	}
//
//	if (rs->state & rs_connected)
//		rs_process_cq(rs, 0, rs_conn_all_sends_done);
//
//out:
//	if ((rs->fd_flags & O_NONBLOCK) && (rs->state & rs_connected))
//		rs_set_nonblocking(rs, rs->fd_flags);
//
//	if (rs->state & rs_disconnected) {
//		/* Generate event by flushing receives to unblock rpoll */
//		ibv_req_notify_cq(rs->cm_id->recv_cq, 0);
//		ucma_shutdown(rs->cm_id);
//	}
//
//	return ret;
//}

void gen_portal_close(struct gen_portal *port)
{
	fi_close
}
//int rclose(int socket)
//{
//	struct rsocket *rs;
//
//	rs = idm_lookup(&idm, socket);
//	if (!rs)
//		return EBADF;
//	if (rs->type == SOCK_STREAM) {
//		if (rs->state & rs_connected)
//			rshutdown(socket, SHUT_RDWR);
//		else if (rs->opts & RS_OPT_SVC_ACTIVE)
//			rs_notify_svc(&tcp_svc, rs, RS_SVC_REM_KEEPALIVE);
//	} else {
//		ds_shutdown(rs);
//	}
//
//	rs_free(rs);
//	return 0;
//}
