/*
 * Copyright (c) 2017 Intel Corporation, Inc.  All rights reserved.
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

#include <config.h>
#include <stdlib.h>
#include <fi_util.h>
#include <fi_iov.h>
#include <ofi_mr.h>
#include <fi_list.h>


static int util_mr_find_overlap(void *a, void *b)
{
	struct iovec *iov1 = a, *iov2 = b;

	if (ofi_iov_left(iov1, iov2))
		return -1;
	else if (ofi_iov_right(iov1, iov2))
		return 1;
	else
		return 0;
}

static void util_mr_free_entry(struct ofi_mr_cache *cache,
			       struct ofi_mr_entry *entry)
{
	RbtIterator iter;

	FI_DBG(cache->domain->prov, FI_LOG_MR,
	       "freeing %p:%"PRIu64"\n",
	       entry->iov.iov_base, entry->iov.iov_len);

	if (!entry->retired) {
		iter = rbtFind(cache->mr_tree, &entry->iov);
		if (OFI_LIKELY(iter != NULL)) {
			(void)rbtErase(cache->mr_tree, iter);
		}
	}
	ofi_monitor_unsubscribe(entry->iov.iov_base, entry->iov.iov_len,
				&entry->subscription);
	cache->delete_region(cache, entry);
	free(entry);

	cache->cached_cnt--;
}

static void
util_mr_cache_process_notifier_events(struct ofi_mr_cache *cache)
{
	struct ofi_mr_entry *entry;
	struct ofi_subscription *subscription;
	RbtIterator iter;

	while ((subscription = ofi_monitor_get_event(&cache->nq))) {
		entry = container_of(subscription, struct ofi_mr_entry,
				     subscription);
		if (entry->use_cnt == 0) {
			dlist_remove(&entry->lru_entry);
			util_mr_free_entry(cache, entry);
		} else {
			if (!entry->retired) {
				iter = rbtFind(cache->mr_tree, &entry->iov);
				if (OFI_LIKELY(iter != NULL)) {
					(void)rbtErase(cache->mr_tree, iter);
				}
				entry->retired = 1;
			}
		}
	}
}

static void util_mr_cache_flush(struct ofi_mr_cache *cache)
{
	struct ofi_mr_entry *entry;

	util_mr_cache_process_notifier_events(cache);

	while ((cache->cached_cnt >= cache->size) &&
	       !dlist_empty(&cache->lru_list)) {
		dlist_pop_front(&cache->lru_list, struct ofi_mr_entry,
				entry, lru_entry);
		util_mr_free_entry(cache, entry);
	}
}

void ofi_mr_cache_delete(struct ofi_mr_cache *cache, struct ofi_mr_entry *entry)
{
	FI_DBG(cache->domain->prov, FI_LOG_MR,
	       "delete %p\n", entry->iov.iov_base);
	cache->delete_cnt++;

	util_mr_cache_process_notifier_events(cache);

	if (--entry->use_cnt == 0) {
		if (entry->retired) {
			util_mr_free_entry(cache, entry);
		} else {
			dlist_insert_tail(&entry->lru_entry, &cache->lru_list);
		}
	}
}

static int
util_mr_cache_create(struct ofi_mr_cache *cache, const struct fi_mr_attr *attr,
		     struct ofi_mr_entry **entry)
{
	int ret;

	FI_DBG(cache->domain->prov, FI_LOG_MR,
	       "creating %p:%"PRIu64"\n",
	       attr->mr_iov->iov_base, attr->mr_iov->iov_len);
	*entry = calloc(1, sizeof(**entry) + cache->entry_data_size);
	if (!*entry)
		return -FI_ENOMEM;

	(*entry)->attr.access = attr->access;
	(*entry)->attr.offset = attr->offset;
	(*entry)->attr.requested_key = attr->requested_key;
	(*entry)->attr.context = attr->context;
	(*entry)->attr.auth_key_size = attr->auth_key_size;
	(*entry)->attr.auth_key = attr->auth_key;
	(*entry)->iov = *attr->mr_iov;
	(*entry)->use_cnt = 1;

	ret = cache->add_region(cache, *entry);
	if (ret) {
		free(*entry);
		return ret;
	}

	if (++cache->cached_cnt > cache->size) {
		(*entry)->retired = 1;
	} else {
		ret = ofi_monitor_subscribe(&cache->nq, (*entry)->iov.iov_base,
					    (*entry)->iov.iov_len,
					    &(*entry)->subscription);
		if (ret)
			goto err_subscribe;
		if (rbtInsert(cache->mr_tree, &(*entry)->iov, *entry)) {
			util_mr_free_entry(cache, *entry);
			ret = -FI_ENOMEM;
			goto err_rbtInsert;
		}
	}

	return 0;
err_rbtInsert:
	ofi_monitor_unsubscribe((*entry)->iov.iov_base, (*entry)->iov.iov_len,
				&(*entry)->subscription);
err_subscribe:
	util_mr_free_entry(cache, *entry);
	return ret;
}

static int
util_mr_cache_merge(struct ofi_mr_cache *cache, const struct fi_mr_attr *attr,
		    RbtIterator iter, struct ofi_mr_entry **entry)
{
	struct iovec iov, *old_iov;
	struct ofi_mr_entry *old_entry;
	struct fi_mr_attr mr_attr;

	iov = *attr->mr_iov;
	do {
		rbtKeyValue(cache->mr_tree, iter, (void **) &old_iov,
			    (void **) &old_entry);

		iov.iov_base = MIN(iov.iov_base, old_iov->iov_base);
		iov.iov_len = ((uintptr_t)
			MAX(ofi_iov_end(&iov), ofi_iov_end(old_iov))) -
			((uintptr_t) iov.iov_base);

		rbtErase(cache->mr_tree, iter);
		if (old_entry->use_cnt) {
			old_entry->retired = 1;
		} else {
			dlist_remove(&old_entry->lru_entry);
			util_mr_free_entry(cache, old_entry);
		}

	} while ((iter = rbtFind(cache->mr_tree, &iov)));

	mr_attr = *attr;
	mr_attr.mr_iov = &iov;

	return util_mr_cache_create(cache, &mr_attr, entry);
}

int ofi_mr_cache_search(struct ofi_mr_cache *cache, const struct fi_mr_attr *attr,
			struct ofi_mr_entry **entry)
{
	RbtIterator iter;
	struct iovec *iov;

	util_mr_cache_process_notifier_events(cache);

	assert(attr->iov_count == 1);
	FI_DBG(cache->domain->prov, FI_LOG_MR,
	       "search %p:%"PRIu64"\n",
	       attr->mr_iov->iov_base, attr->mr_iov->iov_len);
	cache->search_cnt++;

	if (cache->cached_cnt > cache->size)
		util_mr_cache_flush(cache);

	iter = rbtFind(cache->mr_tree, (void *) attr->mr_iov);
	if (!iter) {
		return util_mr_cache_create(cache, attr, entry);
	}

	rbtKeyValue(cache->mr_tree, iter, (void **) &iov, (void **) entry);

	if (!ofi_iov_within(attr->mr_iov, iov))
		return util_mr_cache_merge(cache, attr, iter, entry);

	cache->hit_cnt++;
	if ((*entry)->use_cnt++ == 0)
		dlist_remove(&(*entry)->lru_entry);

	FI_DBG(cache->domain->prov, FI_LOG_MR,
	       "found %p:%"PRIu64"\n",
	       (*entry)->iov.iov_base, (*entry)->iov.iov_len);

	return 0;
}

void ofi_mr_cache_cleanup(struct ofi_mr_cache *cache)
{
	struct ofi_mr_entry *entry;
	struct dlist_entry *tmp;
	RbtIterator iter;

	FI_INFO(cache->domain->prov, FI_LOG_MR, "MR cache stats: "
		"searches %" PRIu64 ", deletes %" PRIu64 ", hits %" PRIu64 "\n",
		cache->search_cnt, cache->delete_cnt, cache->hit_cnt);

	dlist_foreach_container_safe(&cache->lru_list, struct ofi_mr_entry,
				     entry, lru_entry, tmp) {
		assert(entry->use_cnt == 0);
		iter = rbtFind(cache->mr_tree, &entry->iov);
		assert(iter);
		rbtErase(cache->mr_tree, iter);
		dlist_remove(&entry->lru_entry);
		util_mr_free_entry(cache, entry);
	}
	rbtDelete(cache->mr_tree);
	ofi_monitor_del_queue(&cache->nq);
	ofi_atomic_dec32(&cache->domain->ref);
	assert(cache->cached_cnt == 0);
}

int ofi_mr_cache_init(struct util_domain *domain, struct ofi_mem_monitor *monitor,
		      struct ofi_mr_cache *cache)
{
	assert(cache->add_region && cache->delete_region);

	cache->mr_tree = rbtNew(util_mr_find_overlap);
	if (!cache->mr_tree)
		return -FI_ENOMEM;

	cache->domain = domain;
	ofi_atomic_inc32(&domain->ref);

	ofi_monitor_add_queue(monitor, &cache->nq);

	dlist_init(&cache->lru_list);
	cache->cached_cnt = 0;
	cache->search_cnt = 0;
	cache->delete_cnt = 0;
	cache->hit_cnt = 0;

	return 0;
}
