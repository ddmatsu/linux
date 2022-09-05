/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */

#ifndef RXE_RESP_H
#define RXE_RESP_H

enum resp_states rxe_process_atomic(struct rxe_qp *qp,
				    struct rxe_pkt_info *pkt, u64 *vaddr);

#endif /* RXE_RESP_H */
