// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "rxe.h"

static struct workqueue_struct *rxe_wq;

int rxe_alloc_wq(void)
{
	rxe_wq = alloc_workqueue("rxe_wq", WQ_CPU_INTENSIVE, WQ_MAX_ACTIVE);
	if (!rxe_wq)
		return -ENOMEM;

	return 0;
}

void rxe_destroy_wq(void)
{
	destroy_workqueue(rxe_wq);
}

int __rxe_do_task(struct rxe_task *task)

{
	int ret;

	while ((ret = task->func(task->arg)) == 0)
		;

	task->ret = ret;

	return ret;
}

/*
 * this locking is due to a potential race where
 * a second caller finds the task already running
 * but looks just after the last call to func
 */
static void do_task(struct work_struct *w)
{
	int cont;
	int ret;
	struct rxe_task *task = container_of(w, typeof(*task), work);
	struct rxe_qp *qp = (struct rxe_qp *)task->arg;
	unsigned int iterations = RXE_MAX_ITERATIONS;

	spin_lock_bh(&task->lock);
	switch (task->state) {
	case TASK_STATE_START:
		task->state = TASK_STATE_BUSY;
		spin_unlock_bh(&task->lock);
		break;

	case TASK_STATE_BUSY:
		task->state = TASK_STATE_ARMED;
		fallthrough;
	case TASK_STATE_ARMED:
		spin_unlock_bh(&task->lock);
		return;

	default:
		spin_unlock_bh(&task->lock);
		rxe_dbg_qp(qp, "failed with bad state %d\n", task->state);
		return;
	}

	do {
		cont = 0;
		ret = task->func(task->arg);

		spin_lock_bh(&task->lock);
		switch (task->state) {
		case TASK_STATE_BUSY:
			if (ret) {
				task->state = TASK_STATE_START;
			} else if (iterations--) {
				cont = 1;
			} else {
				/* reschedule the work item and exit
				 * the loop to give up the cpu
				 */
				queue_work(task->workq, &task->work);
				task->state = TASK_STATE_START;
			}
			break;

		/* someone tried to run the task since the last time we called
		 * func, so we will call one more time regardless of the
		 * return value
		 */
		case TASK_STATE_ARMED:
			task->state = TASK_STATE_BUSY;
			cont = 1;
			break;

		default:
			rxe_dbg_qp(qp, "failed with bad state %d\n",
					task->state);
		}
		spin_unlock_bh(&task->lock);
	} while (cont);

	task->ret = ret;
}

int rxe_init_task(struct rxe_task *task, void *arg, int (*func)(void *))
{
	task->arg	= arg;
	task->func	= func;
	task->destroyed	= false;

	INIT_WORK(&task->work, do_task);
	task->workq = rxe_wq;

	task->state = TASK_STATE_START;
	spin_lock_init(&task->lock);

	return 0;
}

void rxe_cleanup_task(struct rxe_task *task)
{
	bool idle;

	/*
	 * Mark the task, then wait for it to finish. It might be
	 * running in a non-workqueue (direct call) context.
	 */
	task->destroyed = true;
	flush_workqueue(task->workq);

	do {
		spin_lock_bh(&task->lock);
		idle = (task->state == TASK_STATE_START);
		spin_unlock_bh(&task->lock);
	} while (!idle);
}

void rxe_run_task(struct rxe_task *task)
{
	if (task->destroyed)
		return;

	do_task(&task->work);
}

void rxe_sched_task(struct rxe_task *task)
{
	if (task->destroyed)
		return;

	/*
	 * busy-loop while qp reset is in progress.
	 * This may be called from softirq context and thus cannot sleep.
	 */
	while (atomic_read(&task->suspended))
		cpu_relax();

	queue_work(task->workq, &task->work);
}

void rxe_disable_task(struct rxe_task *task)
{
	/* Alternative to tasklet_disable() */
	atomic_inc(&task->suspended);
	smp_mb__after_atomic();
	flush_workqueue(task->workq);
}

void rxe_enable_task(struct rxe_task *task)
{
	/* Alternative to tasklet_enable() */
	smp_mb__before_atomic();
	atomic_dec(&task->suspended);
}
