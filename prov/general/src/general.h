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

#include <pthread.h>

#include <rdma/fabric.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_msg.h>
#include <rdma/fi_prov.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_trigger.h>
#include <netdb.h>

#include <fi.h>
#include <fi_enosys.h>
//#include <fi_indexer.h>
//#include <fi_rbuf.h>
#include <fi_list.h>

#ifndef _GENERAL_H_
#define _GENERAL_H_


struct gen_fabric {
	struct fid_fabric fid;
	struct fid_fabric *prov_fabric;
	struct dlist_entry domain_list;
	atomic_t refcnt;
	fastlock_t lock;
};

struct gen_domain {
	struct fid_domain fid;
	struct gen_fabric *fabric;
	struct fid_domain *prov_domain;
	atomic_t refcnt;
};

struct gen_av {
	struct fid_av fid;
	struct gen_domain *domain;
	atomic_t refcnt;

	/* default attributes for MSG EPs */
	// tx_size
	// rx_size
	// tx_buf_size
	// rx_buf_size
};

struct gen_portal;
struct gen_tx_cmd;

#endif /* _GENERAL_H_ */
