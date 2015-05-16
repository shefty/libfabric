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

//#include <asm/types.h>
//#include <errno.h>
//#include <fcntl.h>
//#include <netinet/in.h>
//#include <poll.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//#include <assert.h>
//#include <pthread.h>

#include "fi.h"
#include "fi_enosys.h"
#include <rdma/fi_log.h>
#include "prov.h"
#include "general.h"


#define GEN_PROV_NAME "general"
#define GEN_PROV_VERS FI_VERSION(1,0)


static void gen_fini(void)
{
}

static struct fi_provider gen_prov = {
	.name = GEN_PROV_NAME,
	.version = GEN_PROV_VERS,
	.fi_version = FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION),
//	.getinfo = gen_getinfo,
//	.fabric = gen_fabric,
	.cleanup = gen_fini
};

GENERAL_INI
{
	return &gen_prov;
}
