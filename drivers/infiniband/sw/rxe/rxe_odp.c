// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022 Fujitsu Ltd. All rights reserved.
 */

#include <linux/hmm.h>

#include <rdma/ib_umem_odp.h>

#include "rxe.h"
#include "rxe_resp.h"

static bool rxe_ib_invalidate_range(struct mmu_interval_notifier *mni,
				    const struct mmu_notifier_range *range,
				    unsigned long cur_seq)
{
	struct ib_umem_odp *umem_odp =
		container_of(mni, struct ib_umem_odp, notifier);
	unsigned long start;
	unsigned long end;

	if (!mmu_notifier_range_blockable(range))
		return false;

	mutex_lock(&umem_odp->umem_mutex);
	mmu_interval_set_seq(mni, cur_seq);

	start = max_t(u64, ib_umem_start(umem_odp), range->start);
	end = min_t(u64, ib_umem_end(umem_odp), range->end);

	ib_umem_odp_unmap_dma_pages(umem_odp, start, end);

	mutex_unlock(&umem_odp->umem_mutex);
	return true;
}

const struct mmu_interval_notifier_ops rxe_mn_ops = {
	.invalidate = rxe_ib_invalidate_range,
};

#define RXE_PAGEFAULT_RDONLY BIT(1)
#define RXE_PAGEFAULT_SNAPSHOT BIT(2)
static int rxe_odp_do_pagefault(struct rxe_mr *mr, u64 user_va, int bcnt, u32 flags)
{
	int np;
	u64 access_mask;
	bool fault = !(flags & RXE_PAGEFAULT_SNAPSHOT);
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);

	access_mask = ODP_READ_ALLOWED_BIT;
	if (umem_odp->umem.writable && !(flags & RXE_PAGEFAULT_RDONLY))
		access_mask |= ODP_WRITE_ALLOWED_BIT;

	/*
	 * ib_umem_odp_map_dma_and_lock() locks umem_mutex on success.
	 * Callers must release the lock later to let invalidation handler
	 * do its work again.
	 */
	np = ib_umem_odp_map_dma_and_lock(umem_odp, user_va, bcnt,
					  access_mask, fault);

	return np;
}

static int rxe_init_odp_mr(struct rxe_mr *mr)
{
	int ret;
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);

	ret = rxe_odp_do_pagefault(mr, mr->umem->address, mr->umem->length,
				   RXE_PAGEFAULT_SNAPSHOT);

	if (ret >= 0)
		mutex_unlock(&umem_odp->umem_mutex);

	return ret >= 0 ? 0 : ret;
}

int rxe_create_user_odp_mr(struct ib_pd *pd, u64 start, u64 length, u64 iova,
			   int access_flags, struct rxe_mr *mr)
{
	int err;
	struct ib_umem_odp *umem_odp;
	struct rxe_dev *dev = container_of(pd->device, struct rxe_dev, ib_dev);

	if (!IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING))
		return -EOPNOTSUPP;

	rxe_mr_init(access_flags, mr);

	if (!start && length == U64_MAX) {
		if (iova != 0)
			return -EINVAL;
		if (!(dev->attr.odp_caps.general_caps & IB_ODP_SUPPORT_IMPLICIT))
			return -EINVAL;

		/* Never reach here, for implicit ODP is not implemented. */
	}

	umem_odp = ib_umem_odp_get(pd->device, start, length, access_flags,
				   &rxe_mn_ops);
	if (IS_ERR(umem_odp))
		return PTR_ERR(umem_odp);

	umem_odp->private = mr;

	mr->odp_enabled = true;
	mr->ibmr.pd = pd;
	mr->umem = &umem_odp->umem;
	mr->access = access_flags;
	mr->ibmr.length = length;
	mr->ibmr.iova = iova;
	mr->offset = ib_umem_offset(&umem_odp->umem);
	mr->state = RXE_MR_STATE_VALID;
	mr->ibmr.type = IB_MR_TYPE_USER;

	err = rxe_init_odp_mr(mr);

	return err;
}

static inline bool rxe_is_pagefault_neccesary(struct ib_umem_odp *umem_odp,
					      u64 iova, int length, u32 perm)
{
	int idx;
	u64 addr;
	bool need_fault = false;

	addr = iova & (~(BIT(umem_odp->page_shift) - 1));

	/* Skim through all pages that are to be accessed. */
	while (addr < iova + length) {
		idx = (addr - ib_umem_start(umem_odp)) >> umem_odp->page_shift;

		if (!(umem_odp->dma_list[idx] & perm)) {
			need_fault = true;
			break;
		}

		addr += BIT(umem_odp->page_shift);
	}
	return need_fault;
}

/* umem mutex must be locked before entering this function. */
static int rxe_odp_map_range(struct rxe_mr *mr, u64 iova, int length, u32 flags)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	const int max_tries = 3;
	int cnt = 0;

	int err;
	u64 perm;
	bool need_fault;

	if (unlikely(length < 1)) {
		mutex_unlock(&umem_odp->umem_mutex);
		return -EINVAL;
	}

	perm = ODP_READ_ALLOWED_BIT;
	if (!(flags & RXE_PAGEFAULT_RDONLY))
		perm |= ODP_WRITE_ALLOWED_BIT;

	/*
	 * A successful return from rxe_odp_do_pagefault() does not guarantee
	 * that all pages in the range became present. Recheck the DMA address
	 * array, allowing max 3 tries for pagefault.
	 */
	while ((need_fault = rxe_is_pagefault_neccesary(umem_odp,
							iova, length, perm))) {

		if (cnt >= max_tries)
			break;

		mutex_unlock(&umem_odp->umem_mutex);

		/* umem_mutex is locked on success. */
		err = rxe_odp_do_pagefault(mr, iova, length, flags);
		if (err < 0)
			return err;

		cnt++;
	}

	if (need_fault)
		return -EFAULT;

	return 0;
}

static inline void *rxe_odp_get_virt(struct ib_umem_odp *umem_odp, int umem_idx,
				     size_t offset)
{
	struct page *page;
	void *virt;

	/*
	 * Step 1. Get page struct from the pfn array.
	 * Step 2. Convert page struct to kernel logical address.
	 * Step 3. Add offset in the page to the address.
	 */
	page = hmm_pfn_to_page(umem_odp->pfn_list[umem_idx]);
	virt = page_address(page);

	if (!virt)
		return NULL;

	virt += offset;

	return virt;
}

static int __rxe_odp_mr_copy(struct rxe_mr *mr, u64 iova, void *addr,
			     int length, enum rxe_mr_copy_dir dir)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);

	int idx, bytes;
	u8 *user_va;
	size_t offset;

	idx = (iova - ib_umem_start(umem_odp)) >> umem_odp->page_shift;
	offset = iova & (BIT(umem_odp->page_shift) - 1);

	while (length > 0) {
		u8 *src, *dest;

		user_va = (u8 *)rxe_odp_get_virt(umem_odp, idx, offset);
		if (!user_va)
			return -EFAULT;

		src = (dir == RXE_TO_MR_OBJ) ? addr : user_va;
		dest = (dir == RXE_TO_MR_OBJ) ? user_va : addr;

		bytes = BIT(umem_odp->page_shift) - offset;

		if (bytes > length)
			bytes = length;

		memcpy(dest, src, bytes);

		length  -= bytes;
		idx++;
		offset = 0;
	}

	return 0;
}

int rxe_odp_mr_copy(struct rxe_mr *mr, u64 iova, void *addr, int length,
		    enum rxe_mr_copy_dir dir)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	u32 flags = 0;

	int err;

	if (length == 0)
		return 0;

	if (unlikely(!mr->odp_enabled))
		return -EOPNOTSUPP;

	switch (dir) {
	case RXE_TO_MR_OBJ:
		break;

	case RXE_FROM_MR_OBJ:
		flags = RXE_PAGEFAULT_RDONLY;
		break;

	default:
		return -EINVAL;
	}

	/* If pagefault is not required, umem mutex will be held until data
	 * copy to the MR completes. Otherwise, it is released and locked
	 * again in rxe_odp_map_range() to let invalidation handler do its
	 * work meanwhile.
	 */
	mutex_lock(&umem_odp->umem_mutex);

	err = rxe_odp_map_range(mr, iova, length, flags);
	if (err)
		return err;

	err =  __rxe_odp_mr_copy(mr, iova, addr, length, dir);

	mutex_unlock(&umem_odp->umem_mutex);

	return err;
}

static inline void *rxe_odp_get_virt_atomic(struct rxe_qp *qp, struct rxe_mr *mr)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	u64 iova = qp->resp.va + qp->resp.offset;
	int idx;
	size_t offset;

	if (rxe_odp_map_range(mr, iova, sizeof(char), 0))
		return NULL;

	idx = (iova - ib_umem_start(umem_odp)) >> umem_odp->page_shift;
	offset = iova & (BIT(umem_odp->page_shift) - 1);

	return rxe_odp_get_virt(umem_odp, idx, offset);
}

enum resp_states rxe_odp_atomic_ops(struct rxe_qp *qp, struct rxe_pkt_info *pkt,
				    struct rxe_mr *mr)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	u64 *vaddr;
	int ret;

	if (unlikely(!mr->odp_enabled))
		return RESPST_ERR_RKEY_VIOLATION;

	/* If pagefault is not required, umem mutex will be held until the
	 * atomic operation completes. Otherwise, it is released and locked
	 * again in rxe_odp_map_range() to let invalidation handler do its
	 * work meanwhile.
	 */
	mutex_lock(&umem_odp->umem_mutex);

	vaddr = (u64 *)rxe_odp_get_virt_atomic(qp, mr);
	if (!vaddr)
		return RESPST_ERR_RKEY_VIOLATION;

	if (pkt->mask & RXE_ATOMIC_MASK)
		ret = rxe_process_atomic(qp, pkt, vaddr);
	else
		ret = RESPST_ERR_UNSUPPORTED_OPCODE;

	mutex_unlock(&umem_odp->umem_mutex);
	return ret;
}
