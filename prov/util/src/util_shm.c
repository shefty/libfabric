/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
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

#include "config.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fi_shm.h>


/* TODO: Determine if aligning SMR data helps performance */
int smr_create(const struct fi_provider *prov,
	       const struct smr_attr *attr, struct shm_region **smr)
{
	size_t total_size, peer_offset, cmd_queue_offset, tx_ctx_offset;
	size_t resp_queue_offset, inject_pool_offset, name_offset;
	int fd, ret;

	peer_offset = sizeof(**smr);
	cmd_queue_offset = peer_offset + sizeof(struct smr_peer) +
			sizeof(struct shm_region *) * attr->peer_count;
	tx_ctx_offset = cmd_queue_offset + sizeof(struct smr_cmd_queue) +
			sizeof(struct smr_cmd) * attr->rx_count;
	resp_queue_offset = tx_ctx_offset + sizeof(struct smr_tx_ctx) +
			sizeof(struct smr_req) * attr->tx_count;
	inject_pool_offset = resp_queue_offset + sizeof(struct smr_resp_queue) +
			sizeof(struct smr_resp) * attr->tx_count;
	name_offset = inject_pool_offset + sizeof(struct smr_inject_pool) +
			sizeof(struct smr_inject_buf) * attr->tx_count;
	total_size = name_offset + strlen(attr->name) + 1;
	*smr = calloc(1, total_size);
	if (!*smr) {
		FI_WARN(prov, FI_LOG_EP_CTRL, "failed to alloc SHM region\n");
		return -FI_ENOMEM;
	}

	(*smr)->version = SMR_VERSION;
	(*smr)->flags = SMR_FLAG_ATOMIC | SMR_FLAG_DEBUG;
	(*smr)->pid = getpid();
	atomic_initialize(&(*smr)->lock, 0);
	(*smr)->prov = prov;

	(*smr)->total_size = total_size;
	(*smr)->peer_offset = peer_offset;
	(*smr)->cmd_queue_offset = cmd_queue_offset;
	(*smr)->tx_ctx_offset = tx_ctx_offset;
	(*smr)->resp_queue_offset = resp_queue_offset;
	(*smr)->inject_pool_offset = inject_pool_offset;
	(*smr)->name_offset = name_offset;

	smr_peer_init(smr_peer(*smr), attr->peer_count);
	smr_cmd_queue_init(smr_cmd_queue(*smr), attr->rx_count);
	smr_tx_ctx_init(smr_tx_ctx(*smr), attr->tx_count);
	smr_resp_queue_init(smr_resp_queue(*smr), attr->tx_count);
	smr_inject_pool_init(smr_inject_pool(*smr), attr->tx_count);
	strncpy((char *) smr_name(*smr), attr->name, total_size - name_offset);

	fd = shm_open(attr->name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		FI_WARN(prov, FI_LOG_EP_CTRL, "shm_open error\n");
		goto err1;
	}

	ret = ftruncate(fd, total_size);
	if (ret < 0) {
		FI_WARN(prov, FI_LOG_EP_CTRL, "ftruncate error\n");
		goto err2;
	}

	(*smr)->map = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, 0);
	if ((*smr)->map == MAP_FAILED) {
		FI_WARN(prov, FI_LOG_EP_CTRL, "mmap error\n");
		goto err2;
	}

	/* TODO: If we unlink here, can other processes open the region? */
	close(fd);
	return 0;

err2:
	shm_unlink(attr->name);
	close(fd);
err1:
	free(*smr);
	return -errno;
}

int smr_map(struct shm_region *smr, const char *name, int *id)
{
	struct shm_region *peer;
	size_t size;
	int fd, ret;

	fd = shm_open(name, O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		FI_WARN(smr->prov, FI_LOG_EP_CTRL, "shm_open error\n");
		return -errno;
	}

	peer = mmap(NULL, sizeof(*peer), PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (peer == MAP_FAILED) {
		FI_WARN(smr->prov, FI_LOG_EP_CTRL, "mmap error\n");
		ret = -errno;
		goto out;
	}

	size = peer->total_size;
	munmap(peer, sizeof(*peer));

	peer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (peer == MAP_FAILED) {
		FI_WARN(smr->prov, FI_LOG_EP_CTRL, "mmap error\n");
		ret = -errno;
		goto out;
	}

	smr_lock(smr);
	if (!freestack_isempty(smr_peer(smr))) {
		*id = freestack_pop(smr_peer(smr));
		smr_peer(smr)->buf[*id] = peer;
	} else {
		FI_WARN(smr->prov, FI_LOG_EP_CTRL, "peer array is full\n");
		ret = -FI_ENOMEM;
	}
	smr_unlock(smr);
out:
	close(fd);
	return ret;
}

void smr_unmap(struct shm_region, int id)
{
	munmap(smr_peer_region(smr, i), smr_peer_region(smr, i)->total_size);
}

void smr_free(struct shm_region *smr)
{
	int i;

	for (i = 0; i < smr_peer(smr)->size; i++) {
		if (smr_peer(smr)->buf[i] >= smr_peer(smr)->size)
			smr_unmap(smr, i);
	}
	shm_unlink(smr_name(smr));
	free(smr);
}
