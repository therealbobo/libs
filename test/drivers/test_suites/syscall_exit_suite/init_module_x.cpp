#include "../../event_class/event_class.h"

#if defined(__NR_init_module)

#if defined(__NR_close) && defined(__NR_open) && defined(__NR_read)
TEST(SyscallExit, init_moduleX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_init_module, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open /dev/urandom for reading */
	int fd = syscall(__NR_open, "/dev/urandom", O_RDONLY);
	assert_syscall_state(SYSCALL_SUCCESS, "open", fd, NOT_EQUAL, -1);

	/* Read data from /dev/urandom */
	const unsigned data_len = DEFAULT_SNAPLEN / 2;
	char mock_img[data_len];
	ssize_t read_bytes = syscall(__NR_read, fd, (void *)mock_img, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "read", read_bytes, NOT_EQUAL, 0);

	char mock_buf[] = "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAA\0";

	/*
	 * Call the `init_module`
	 */
	assert_syscall_state(SYSCALL_FAILURE, "init_module", syscall(__NR_init_module, (void*)mock_img, data_len, (void *)mock_buf));
	int64_t errno_value = -errno;

	/* Close /dev/urandom fd */
	syscall(__NR_close, fd);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: img (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, mock_img, read_bytes);

	/* Parameter 3: length (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)data_len);

	/* Parameter 4: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(4, mock_buf);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

#endif
