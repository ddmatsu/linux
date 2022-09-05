/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_WQ_H
#define RXE_WQ_H

enum {
	WQ_STATE_START	= 0,
	WQ_STATE_BUSY		= 1,
	WQ_STATE_ARMED	= 2,
};

/*
 * data structure to describe a 'work' which is a short
 * function that returns 0 as long as it needs to be
 * called again.
 */
struct rxe_work {
	struct workqueue_struct	*worker;
	struct work_struct	work;
	int			state;
	spinlock_t		state_lock; /* spinlock for work state */
	void			*arg;
	int			(*func)(void *arg);
	int			ret;
	char			name[16];
	bool			destroyed;
	atomic_t		suspended; /* used to {dis,en}able workqueue */
};

/*
 * init rxe_work structure
 *	arg  => parameter to pass to fcn
 *	func => function to call until it returns != 0
 */
int rxe_init_work(struct rxe_work *work,
		  void *arg, int (*func)(void *), char *name);

/* cleanup work */
void rxe_cleanup_work(struct rxe_work *work);

/*
 * raw call to func in loop without any checking
 * can call when workqueues are suspended.
 */
int __rxe_do_work(struct rxe_work *work);

/*
 * common function called by any of the main workqueues
 * If there is any chance that there is additional
 * work to do someone must reschedule the work before
 * leaving
 */
void rxe_do_work(struct work_struct *w);

/* run a work, else schedule it to run as a workqueue, The decision
 * to run or schedule workqueue is based on the parameter sched.
 */
void rxe_run_work(struct rxe_work *work, int sched);

/* keep a work from scheduling */
void rxe_disable_work(struct rxe_work *work);

/* allow work to run */
void rxe_enable_work(struct rxe_work *work);

#endif /* RXE_WQ_H */
