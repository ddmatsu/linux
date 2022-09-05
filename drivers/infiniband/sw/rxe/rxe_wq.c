// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/hardirq.h>

#include "rxe.h"

int __rxe_do_work(struct rxe_work *work)

{
	int ret;

	while ((ret = work->func(work->arg)) == 0)
		;

	work->ret = ret;

	return ret;
}

/*
 * this locking is due to a potential race where
 * a second caller finds the work already running
 * but looks just after the last call to func
 */
void rxe_do_work(struct work_struct *w)
{
	int cont;
	int ret;

	struct rxe_work *work = container_of(w, typeof(*work), work);
	unsigned int iterations = RXE_MAX_ITERATIONS;

	spin_lock_bh(&work->state_lock);
	switch (work->state) {
	case WQ_STATE_START:
		work->state = WQ_STATE_BUSY;
		spin_unlock_bh(&work->state_lock);
		break;

	case WQ_STATE_BUSY:
		work->state = WQ_STATE_ARMED;
		fallthrough;
	case WQ_STATE_ARMED:
		spin_unlock_bh(&work->state_lock);
		return;

	default:
		spin_unlock_bh(&work->state_lock);
		pr_warn("%s failed with bad state %d\n", __func__, work->state);
		return;
	}

	do {
		cont = 0;
		ret = work->func(work->arg);

		spin_lock_bh(&work->state_lock);
		switch (work->state) {
		case WQ_STATE_BUSY:
			if (ret) {
				work->state = WQ_STATE_START;
			} else if (iterations--) {
				cont = 1;
			} else {
				/* reschedule the work and exit
				 * the loop to give up the cpu
				 */
				queue_work(work->worker, &work->work);
				work->state = WQ_STATE_START;
			}
			break;

		/* someone tried to run the work since the last time we called
		 * func, so we will call one more time regardless of the
		 * return value
		 */
		case WQ_STATE_ARMED:
			work->state = WQ_STATE_BUSY;
			cont = 1;
			break;

		default:
			pr_warn("%s failed with bad state %d\n", __func__,
				work->state);
		}
		spin_unlock_bh(&work->state_lock);
	} while (cont);

	work->ret = ret;
}

int rxe_init_work(struct rxe_work *work,
		  void *arg, int (*func)(void *), char *name)
{
	work->arg	= arg;
	work->func	= func;
	snprintf(work->name, sizeof(work->name), "%s", name);
	work->destroyed	= false;
	atomic_set(&work->suspended, 0);

	work->worker = create_singlethread_workqueue(name);
	INIT_WORK(&work->work, rxe_do_work);

	work->state = WQ_STATE_START;
	spin_lock_init(&work->state_lock);

	return 0;
}

void rxe_cleanup_work(struct rxe_work *work)
{
	bool idle;

	/*
	 * Mark the work, then wait for it to finish. It might be
	 * running in a non-workqueue (direct call) context.
	 */
	work->destroyed = true;
	flush_workqueue(work->worker);

	do {
		spin_lock_bh(&work->state_lock);
		idle = (work->state == WQ_STATE_START);
		spin_unlock_bh(&work->state_lock);
	} while (!idle);

	destroy_workqueue(work->worker);
}

void rxe_run_work(struct rxe_work *work, int sched)
{
	if (work->destroyed)
		return;

	/* busy-loop while qp reset is in progress */
	while (atomic_read(&work->suspended))
		continue;

	if (sched)
		queue_work(work->worker, &work->work);
	else
		rxe_do_work(&work->work);
}

void rxe_disable_work(struct rxe_work *work)
{
	atomic_inc(&work->suspended);
	flush_workqueue(work->worker);
}

void rxe_enable_work(struct rxe_work *work)
{
	atomic_dec(&work->suspended);
}
