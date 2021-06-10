/*
 * Copyright (c) 2017-2021 Intel Corporation, Inc.  All rights reserved.
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

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include <ofi_proto.h>


#ifndef _TCPX_PROTO_H_
#define _TCPX_PROTO_H_


/*
 * Version 4 definitions
 */

enum {
	TCPX_CM_OP_CONNECT,
	TCPX_CM_OP_ACCEPT,
	TCPX_CM_OP_REJECT,
};

 /* version must be first for compatibility - align with ofi_ctrl_hdr */
struct tcpx_cm_msg_v4 {
	uint8_t version; /* version is set during CM exchange only */
	uint8_t op;
	uint8_t flags;
	uint8_t size;
	uint16_t endian;
	uint16_t error;
	uint8_t data[UINT8_MAX];
};

/* op field:
 * bits 7:6 - reserved
 * bits 5:4 - hdr type (short, standard, extended)
 * bits 3:0 - opcode
 */

/* values limited to 2 bits */
enum {
	TCPX_HDR_SHORT,
	TCPX_HDR_STD,
	TCPX_HDR_EXT,
	/* 1 reserved value available */
	TCPX_HDR_MAX,
};

/* implementation comment:
 * RTS/CTS - ready to send, clear to send, used for rendezvous
 */
/* values limited to 4 bits */
enum {
	TCPX_ACK,
	TCPX_OP_MSG,
	TCPX_OP_MSG_RTS,
	TCPX_OP_MSG_CTS,
	TCPX_OP_MSG_WRITE,
	TCPX_OP_TAG,
	TCPX_OP_TAG_RTS,
	TCPX_OP_TAG_CTS,
	TCPX_OP_TAG_WRITE,
	TCPX_OP_WRITE,
	TCPX_OP_READ_REQ,
	TCPX_OP_READ_RESP,
	TCPX_OP_MAX,
};

static inline uint8_t tcpx_get_hdr_type(uint8_t op)
{
	return op >> 4;
}

static inline void tcpx_set_hdr_op(uint8_t *op, uint8_t type, uint8_t opcode)
{
	assert((type < TCPX_HDR_MAX) && (opcode < TCPX_OP_MAX));
	*op = (type << 4) | opcode;
}

/* flags - 8 bits available */
enum {
	TCPX_ACK_REQ = BIT(0),
	TCPX_CQ_DATA = BIT(1),
};

/* header layout:
 * short, standard, or extended header
 * u64 cq data: if CQ_DATA flag set
 * u32 or u64 tag: if op = OP_TAG
 * rma: if op = {WRITE, WRITE_REQ, READ_REQ}
 */

/* Standard RMA iovec.  Pair with the standard header for RMA transfers
 * < 4GB and that target a single scatter-gather region.
 */
struct tcpx_std_rma {
	uint64_t addr;
	uint32_t len;
	uint32_t key;
};

/* Extended RMA iovec.  Pair with extended header for RMA transfers >= GB
 * or that target multiple scatter-gather regions.
 */
struct tcpx_ext_rma {
	uint64_t		addr;
	uint64_t		len;
	uint64_t		key;
};


/* Short header format supports OP_MSG transfers < 64k, plus internal
 * protocol messages.  It can support OP_TAG transfers for 32-bit tags
 * (upper 32-bits of tag are 0).  Messages with 64-bit protocol fields
 * (e.g. CQ data or RMA target addr) must use the standard or extended
 * header for proper 64-bit field alignment.
 */
struct tcpx_short_hdr {
	uint8_t op;
	uint8_t flags;
	uint16_t size;
};

/* Standard header is expected to support most transfers that cannot use
 * the short header.  Handles transfers < 4GB, RMA operations that target
 * a single memory region, messages carrying CQ data, and tagged messages
 * requiring a 64-bit tag.
 */
struct tcpx_std_hdr {
	uint8_t op;
	uint8_t flags;
	uint8_t hdr_size;
	union {
		uint8_t rsvd;
		uint8_t id; /* debug */
	};
	uint32_t size;
};

/* Extended header is primarily for feature compatibility with the v3 tcp
 * protocol.  Supports transfers >= 4GB and RMA operations that target
 * multiple memory regions.
 */
struct tcpx_ext_hdr {
	uint8_t op;
	uint8_t flags;
	uint8_t hdr_size;
	union {
		uint8_t rsvd;
		uint8_t id; /* debug */
	};
	uint32_t resv; /* alignment */
	uint64_t size;
};

/*
 * Version 3 (compatibility) definitions
 */

#define TCPX_CTRL_HDR_VERSION	3

enum {
	TCPX_MAX_CM_DATA_SIZE = 256
};

struct tcpx_cm_msg {
	struct ofi_ctrl_hdr hdr;
	char data[TCPX_MAX_CM_DATA_SIZE];
};

#define TCPX_HDR_VERSION	3

enum {
	TCPX_IOV_LIMIT = 4
};

/* base_hdr::op_data */
enum {
	/* backward compatible value */
	TCPX_OP_ACK = 2, /* indicates ack message - should be a flag */
};

/* Flags */
#define TCPX_REMOTE_CQ_DATA	(1 << 0)
/* not used TCPX_TRANSMIT_COMPLETE	(1 << 1) */
#define TCPX_DELIVERY_COMPLETE	(1 << 2)
#define TCPX_COMMIT_COMPLETE	(1 << 3)
#define TCPX_TAGGED		(1 << 7)

struct tcpx_base_hdr {
	uint8_t			version;
	uint8_t			op;
	uint16_t		flags;
	uint8_t			op_data;
	uint8_t			rma_iov_cnt;
	uint8_t			hdr_size;
	union {
		uint8_t		rsvd;
		uint8_t		id; /* debug */
	};
	uint64_t		size;
};

struct tcpx_tag_hdr {
	struct tcpx_base_hdr	base_hdr;
	uint64_t		tag;
};

struct tcpx_cq_data_hdr {
	struct tcpx_base_hdr 	base_hdr;
	uint64_t		cq_data;
};

struct tcpx_tag_data_hdr {
	struct tcpx_cq_data_hdr	cq_data_hdr;
	uint64_t		tag;
};

/* Maximum header is scatter RMA with CQ data */
#define TCPX_MAX_HDR (sizeof(struct tcpx_cq_data_hdr) + \
		     sizeof(struct ofi_rma_iov) * TCPX_IOV_LIMIT)

/*
 * End version 3 definitions
 */

#endif //_TCPX_PROTO_H_
