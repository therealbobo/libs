/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(finit_module_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, FINIT_MODULE_E_SIZE, PPME_SYSCALL_FINIT_MODULE_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;


}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(finit_module_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_FINIT_MODULE_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: dirfd (type: PT_FD) */
	s64 fd = (s64)extract__syscall_argument(regs, 0);
	auxmap__store_s64_param(auxmap, fd);

	u16 snaplen = maps__get_snaplen();
	apply_dynamic_snaplen(regs, &snaplen, false);

	/* Parameter 3: uargs (type: PT_CHARBUF) */
	unsigned long uargs_ptr = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, uargs_ptr, snaplen, USER);

	/* Parameter 4: flags (type: PT_INT32) */
	s32 flags = extract__syscall_argument(regs, 2);
	auxmap__store_u32_param(auxmap, (s32)finit_module_flags_to_scap(flags));


	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
