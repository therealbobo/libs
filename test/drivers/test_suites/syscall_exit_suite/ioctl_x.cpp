#include "../../event_class/event_class.h"

#if defined(__NR_ioctl) && defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void run_ioctl_capture_test(int64_t fd, uint64_t request, uint64_t argument, int expected_errno) {
	auto evt_test = get_syscall_event_test(__NR_ioctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* Here we need to call the `ioctl` from a child because the main process throws lots of
	 * `ioctl` to manage the kmod.
	 */
	clone_args cl_args = {};
	cl_args.flags = CLONE_FILES;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0) {
		/* In this way in the father we know if the call was successful or not. */
		if(syscall(__NR_ioctl, fd, request, argument) == -1 && errno == expected_errno) {
			/* SUCCESS because we want the call to fail */
			exit(EXIT_SUCCESS);
		} else {
			exit(EXIT_FAILURE);
		}
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);
	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "wait4",
	                     syscall(__NR_wait4, ret_pid, &status, options, NULL),
	                     NOT_EQUAL,
	                     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0) {
		FAIL() << "The ioctl call is successful while it should fail..." << std::endl;
	}

	/* This is the errno value we expect from the `ioctl` call. */
	int64_t errno_value = -expected_errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(ret_pid);

	if(::testing::Test::HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)fd);

	/* Parameter 3: request (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)request);

	/* Parameter 4: argument (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)argument);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

static void run_ioctl_bad_fd_capture_test(uint64_t request, uint64_t argument) {
	run_ioctl_capture_test(-1, request, argument, EBADF);
}

static void run_ioctl_valid_fd_capture_test(uint64_t request, uint64_t argument) {
	int fd = open("/dev/null", O_RDONLY);
	ASSERT_NE(fd, -1);

	run_ioctl_capture_test(fd, request, argument, ENOTTY);

	ASSERT_EQ(close(fd), 0);
}

TEST(SyscallExit, ioctlX_siocgifcount) {
	run_ioctl_bad_fd_capture_test(SIOCGIFCOUNT, 0);
}

TEST(SyscallExit, ioctlX_valid_fd_unsupported_request) {
	run_ioctl_valid_fd_capture_test(SIOCGIFCOUNT, 0);
}

TEST(SyscallExit, ioctlX_unknown_request) {
	run_ioctl_valid_fd_capture_test(0xFFFFFFFF, 0);
}

TEST(SyscallExit, ioctlX_request_high_bits_preserved) {
	run_ioctl_bad_fd_capture_test(0xFFFFFFFFFFFFFFFFULL, 0);
}

TEST(SyscallExit, ioctlX_argument_high_bits_preserved) {
	run_ioctl_bad_fd_capture_test(SIOCGIFCOUNT, 0xFFFFFFFFFFFFFFFFULL);
}

TEST(SyscallExit, ioctlX_disable_dropping_mode) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_DISABLE_DROPPING_MODE, 0);
}

TEST(SyscallExit, ioctlX_enable_dropping_mode) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_ENABLE_DROPPING_MODE, 8);
}

TEST(SyscallExit, ioctlX_set_snaplen) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_SET_SNAPLEN, 4096);
}

TEST(SyscallExit, ioctlX_disable_dynamic_snaplen) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN, 0);
}

TEST(SyscallExit, ioctlX_enable_dynamic_snaplen) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN, 0);
}

TEST(SyscallExit, ioctlX_get_vtid) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_VTID, 12345);
}

TEST(SyscallExit, ioctlX_get_vpid) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_VPID, 12345);
}

TEST(SyscallExit, ioctlX_get_current_tid) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_CURRENT_TID, 0);
}

TEST(SyscallExit, ioctlX_get_current_pid) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_CURRENT_PID, 0);
}

TEST(SyscallExit, ioctlX_get_proclist) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_PROCLIST, 0x12345678);
}

TEST(SyscallExit, ioctlX_get_n_tracepoint_hit) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_N_TRACEPOINT_HIT, 0x12345678);
}

TEST(SyscallExit, ioctlX_get_driver_version) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_DRIVER_VERSION, 0x12345678);
}

TEST(SyscallExit, ioctlX_set_fullcapture_port_range) {
	uint32_t start_port = 1000;
	uint32_t end_port = 2000;
	uint64_t encoded_port_range = start_port | (end_port << 16);
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_SET_FULLCAPTURE_PORT_RANGE, encoded_port_range);
}

TEST(SyscallExit, ioctlX_set_statsd_port) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_SET_STATSD_PORT, 8125);
}

TEST(SyscallExit, ioctlX_get_api_version) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_API_VERSION, 0x12345678);
}

TEST(SyscallExit, ioctlX_get_schema_version) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_GET_SCHEMA_VERSION, 0x12345678);
}

TEST(SyscallExit, ioctlX_enable_syscall) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_ENABLE_SYSCALL, __NR_close);
}

TEST(SyscallExit, ioctlX_disable_syscall) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_DISABLE_SYSCALL, __NR_close);
}

TEST(SyscallExit, ioctlX_enable_tp) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_ENABLE_TP, 1);
}

TEST(SyscallExit, ioctlX_disable_tp) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_DISABLE_TP, 1);
}

TEST(SyscallExit, ioctlX_enable_dropfailed) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_ENABLE_DROPFAILED, 0);
}

TEST(SyscallExit, ioctlX_disable_dropfailed) {
	run_ioctl_bad_fd_capture_test(PPM_IOCTL_DISABLE_DROPFAILED, 0);
}
#endif
