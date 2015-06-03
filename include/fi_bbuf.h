/*
 * Copyright (c) 2014 Intel Corporation.  All rights reserved.
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
 *
 */

#if !defined(RBUF_H)
#define RBUF_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <fi.h>


/*
 * Simple bounce buffer for data transfers.
 * Similar to ring buffer, but size is limited to 32-bits to match up with
 * flow control data carried in message protocol.
 */
struct bounce_buffer {
	uint32_t	size;
	uint32_t	size_mask;
	uint32_t	rcnt;
	uint32_t	wcnt;
	void		*buf;
};

static inline int bbinit(struct bounce_buffer *bb, uint32_t size)
{
	bb->size = roundup_power_of_two(size);
	bb->size_mask = bb->size - 1;
	bb->rcnt = 0;
	bb->wcnt = 0;
	bb->buf = calloc(1, bb->size);
	if (!bb->buf)
		return -ENOMEM;
	return 0;
}

static inline void bbfree(struct bounce_buffer *bb)
{
	free(bb->buf);
}

static inline int bbfull(struct bounce_buffer *bb)
{
	return bb->wcnt - bb->rcnt >= bb->size;
}

static inline int bbempty(struct bounce_buffer *bb)
{
	return bb->wcnt == bb->rcnt;
}

static inline uint32_t bbused(struct bounce_buffer *bb)
{
	return bb->wcnt - bb->rcnt;
}

static inline uint32_t bbavail(struct bounce_buffer *bb)
{
	return bb->size - rbused(bb);
}

static inline void bbwrite(struct bounce_buffer *bb, const void *buf, uint32_t len)
{
	uint32_t endlen;

	endlen = bb->size - (bb->wcnt & bb->size_mask);
	if (len <= endlen) {
		memcpy((char*) bb->buf + (bb->wcnt & bb->size_mask), buf, len);
	} else {
		memcpy((char*) bb->buf + (bb->wcnt & bb->size_mask), buf, endlen);
		memcpy(bb->buf, (char*) buf + endlen, len - endlen);
	}
	bb->wcnt += len;
}

static inline void bbpeek(struct bounce_buffer *bb, void *buf, size_t len)
{
	uint32_t endlen;

	endlen = bb->size - (bb->rcnt & bb->size_mask);
	if (len <= endlen) {
		memcpy(buf, (char*) bb->buf + (bb->rcnt & bb->size_mask), len);
	} else {
		memcpy(buf, (char*) bb->buf + (bb->rcnt & bb->size_mask), endlen);
		memcpy((char*) buf + endlen, bb->buf, len - endlen);
	}
}

static inline void bbread(struct bounce_buffer *bb, void *buf, uint32_t len)
{
	bbpeek(bb, buf, len);
	bb->rcnt += len;
}


#endif /* BBUF_H */
