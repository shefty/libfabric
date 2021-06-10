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
