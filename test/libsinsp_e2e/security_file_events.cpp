// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

// Ports of the Python e2e tests in test/e2e/tests/test_event_generator/:
//   test_file_writes.py
//   test_make_binary_dirs.py
//   test_modify_binary_dirs.py
//   test_read_sensitive_file.py  (both ReadSensitiveFileUntrusted and
//   ReadSensitiveFileTrustedAfterStartup)

#include "event_capture.h"
#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <linux/limits.h>
#include <string>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

static bool is_open_write_exit(sinsp_evt* evt) {
	uint16_t t = evt->get_type();
	if(t != PPME_SYSCALL_OPEN_X && t != PPME_SYSCALL_OPENAT_2_X && t != PPME_SYSCALL_OPENAT2_X) {
		return false;
	}
	// openat exit: the result is the fd (named "fd"), not "res".
	// A negative fd means failure.
	std::string fd = evt->get_param_value_str("fd", false);
	if(fd.empty() || fd[0] == '-') {
		return false;
	}
	// Must have write flag set.
	std::string flags = evt->get_param_value_str("flags");
	return flags.find("O_WRONLY") != std::string::npos || flags.find("O_RDWR") != std::string::npos;
}

// ─────────────────────────────────────────────────────────────────────────────
// test_file_writes.py — WriteBelowEtc
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_write_below_etc) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	static const char* path = "/etc/created-by-test";
	bool found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return is_open_write_exit(evt) && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) {
		unlink(path);
		int fd = syscall(__NR_openat,
		                 AT_FDCWD,
		                 path,
		                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		                 0755);
		if(fd >= 0) {
			close(fd);
			unlink(path);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		std::string name = param.m_evt->get_param_value_str("name");
		if(name == path) {
			std::string flags = param.m_evt->get_param_value_str("flags");
			EXPECT_NE(std::string::npos, flags.find("O_WRONLY"));
			EXPECT_NE(std::string::npos, flags.find("O_CREAT"));
			EXPECT_NE(std::string::npos, flags.find("O_F_CREATED"));
			std::string fd = param.m_evt->get_param_value_str("fd", false);
			EXPECT_FALSE(fd.empty());
			if(!fd.empty()) {
				EXPECT_NE('-', fd[0]);
			}
			found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_file_writes.py — WriteBelowBinaryDir
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_write_below_binary_dir) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	static const char* path = "/bin/created-by-test";
	bool found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return is_open_write_exit(evt) && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) {
		unlink(path);
		int fd = syscall(__NR_openat,
		                 AT_FDCWD,
		                 path,
		                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		                 0755);
		if(fd >= 0) {
			close(fd);
			unlink(path);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		std::string name = param.m_evt->get_param_value_str("name");
		if(name == path) {
			std::string flags = param.m_evt->get_param_value_str("flags");
			EXPECT_NE(std::string::npos, flags.find("O_WRONLY"));
			EXPECT_NE(std::string::npos, flags.find("O_CREAT"));
			EXPECT_NE(std::string::npos, flags.find("O_F_CREATED"));
			std::string fd = param.m_evt->get_param_value_str("fd", false);
			EXPECT_FALSE(fd.empty());
			if(!fd.empty()) {
				EXPECT_NE('-', fd[0]);
			}
			found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_file_writes.py — CreateFilesBelowDev
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_create_files_below_dev) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	static const char* path = "/dev/created-by-test";
	bool found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return is_open_write_exit(evt) && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) {
		unlink(path);
		int fd = syscall(__NR_openat,
		                 AT_FDCWD,
		                 path,
		                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		                 0755);
		if(fd >= 0) {
			close(fd);
			unlink(path);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		std::string name = param.m_evt->get_param_value_str("name");
		if(name == path) {
			std::string flags = param.m_evt->get_param_value_str("flags");
			EXPECT_NE(std::string::npos, flags.find("O_WRONLY"));
			EXPECT_NE(std::string::npos, flags.find("O_CREAT"));
			EXPECT_NE(std::string::npos, flags.find("O_F_CREATED"));
			std::string fd = param.m_evt->get_param_value_str("fd", false);
			EXPECT_FALSE(fd.empty());
			if(!fd.empty()) {
				EXPECT_NE('-', fd[0]);
			}
			found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_file_writes.py — WriteBelowRpmDatabase
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_write_below_rpm_database) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	// /var/lib/rpm may not exist on all distros — skip if absent.
	if(access("/var/lib/rpm", F_OK) != 0) {
		GTEST_SKIP() << "/var/lib/rpm not present";
	}

	static const char* path = "/var/lib/rpm/created-by-test";
	bool found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return is_open_write_exit(evt) && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) {
		unlink(path);
		int fd = syscall(__NR_openat,
		                 AT_FDCWD,
		                 path,
		                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		                 0755);
		if(fd >= 0) {
			close(fd);
			unlink(path);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		std::string name = param.m_evt->get_param_value_str("name");
		if(name == path) {
			std::string flags = param.m_evt->get_param_value_str("flags");
			EXPECT_NE(std::string::npos, flags.find("O_WRONLY"));
			EXPECT_NE(std::string::npos, flags.find("O_CREAT"));
			EXPECT_NE(std::string::npos, flags.find("O_F_CREATED"));
			std::string fd = param.m_evt->get_param_value_str("fd", false);
			EXPECT_FALSE(fd.empty());
			if(!fd.empty()) {
				EXPECT_NE('-', fd[0]);
			}
			found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_make_binary_dirs.py — MkdirBinaryDirs
// Expect: mkdirat(res=0), unlinkat(res=-EISDIR), unlinkat(AT_REMOVEDIR,res=0)
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_make_binary_dirs) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	static const char* dir_path = "/bin/directory-created-by-test";
	bool mkdirat_found = false;
	bool unlinkat_eisdir_found = false;
	bool unlinkat_removedir_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		uint16_t t = evt->get_type();
		return (t == PPME_SYSCALL_MKDIRAT_X || t == PPME_SYSCALL_UNLINKAT_2_X) && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) {
		// Step 1: create directory
		syscall(__NR_mkdirat, AT_FDCWD, dir_path, 0755);
		// Step 2: try to unlink the directory (will fail with EISDIR)
		syscall(__NR_unlinkat, AT_FDCWD, dir_path, 0);
		// Step 3: remove the directory properly
		syscall(__NR_unlinkat, AT_FDCWD, dir_path, AT_REMOVEDIR);
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		if(e->get_type() == PPME_SYSCALL_MKDIRAT_X) {
			std::string path = e->get_param_value_str("path");
			if(path == dir_path) {
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("-100", e->get_param_value_str("dirfd", false));
				mkdirat_found = true;
			}
		} else if(e->get_type() == PPME_SYSCALL_UNLINKAT_2_X) {
			std::string name = e->get_param_value_str("name");
			if(name == dir_path && !mkdirat_found) {
				return;
			}
			if(name == dir_path) {
				std::string flags = e->get_param_value_str("flags", false);
				std::string res = e->get_param_value_str("res", false);
				if(flags == "0" && !unlinkat_eisdir_found) {
					// EISDIR = 21, returned as -21
					EXPECT_EQ("-21", res);
					unlinkat_eisdir_found = true;
				} else if(flags != "0" && !unlinkat_removedir_found) {
					EXPECT_EQ("0", res);
					unlinkat_removedir_found = true;
				}
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(mkdirat_found);
	EXPECT_TRUE(unlinkat_eisdir_found);
	EXPECT_TRUE(unlinkat_removedir_found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_modify_binary_dirs.py — ModifyBinaryDirs
// Uses a temp file instead of /bin/true to avoid risk.
// Expect: 2x renameat (src→dst, dst→src)
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_modify_binary_dirs) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	static const char* src_path = "/bin/test-rename-src";
	static const char* dst_path = "/bin/test-rename-src.renamed";
	bool rename_fwd_found = false;
	bool rename_bwd_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_type() == PPME_SYSCALL_RENAMEAT_X && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) {
		// Create source file
		int fd = syscall(__NR_openat, AT_FDCWD, src_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
		if(fd >= 0) {
			close(fd);
		}
		// Rename src → dst
		syscall(__NR_renameat, AT_FDCWD, src_path, AT_FDCWD, dst_path);
		// Rename dst → src
		syscall(__NR_renameat, AT_FDCWD, dst_path, AT_FDCWD, src_path);
		// Cleanup
		unlink(src_path);
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		std::string oldpath = e->get_param_value_str("oldpath");
		std::string newpath = e->get_param_value_str("newpath");
		std::string res = e->get_param_value_str("res", false);

		if(oldpath == src_path && newpath == dst_path && !rename_fwd_found) {
			EXPECT_EQ("0", res);
			EXPECT_EQ("-100", e->get_param_value_str("olddirfd", false));
			EXPECT_EQ("-100", e->get_param_value_str("newdirfd", false));
			rename_fwd_found = true;
		} else if(oldpath == dst_path && newpath == src_path && !rename_bwd_found) {
			EXPECT_EQ("0", res);
			rename_bwd_found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(rename_fwd_found);
	EXPECT_TRUE(rename_bwd_found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_read_sensitive_file.py — ReadSensitiveFileUntrusted
// Expect: openat with O_RDONLY on /etc/shadow from the test thread.
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_read_sensitive_file) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	static const char* shadow_path = "/etc/shadow";
	bool found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		uint16_t t = evt->get_type();
		if(t != PPME_SYSCALL_OPEN_X && t != PPME_SYSCALL_OPENAT_2_X &&
		   t != PPME_SYSCALL_OPENAT2_X) {
			return false;
		}
		// Only read opens.
		std::string flags = evt->get_param_value_str("flags");
		bool is_read = flags.find("O_RDONLY") != std::string::npos ||
		               (flags.find("O_WRONLY") == std::string::npos &&
		                flags.find("O_RDWR") == std::string::npos);
		return is_read && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) {
		int fd = syscall(__NR_openat, AT_FDCWD, shadow_path, O_RDONLY | O_CLOEXEC, 0);
		if(fd >= 0) {
			close(fd);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		std::string name = param.m_evt->get_param_value_str("name");
		if(name == shadow_path) {
			// openat exit: result is the fd, named "fd" not "res".
			std::string fd = param.m_evt->get_param_value_str("fd", false);
			EXPECT_FALSE(fd.empty());
			if(!fd.empty()) {
				EXPECT_NE('-', fd[0]);
			}
			found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_read_sensitive_file.py — ReadSensitiveFileTrustedAfterStartup
// Expect: openat with O_RDONLY on /etc/shadow from a child process
// (mirrors the Python test's second parametrized case where a trusted process
// such as httpd reads the file).
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_read_sensitive_file_trusted_after_startup) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	static const char* shadow_path = "/etc/shadow";
	pid_t child_pid = -1;
	bool found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		uint16_t t = evt->get_type();
		if(t != PPME_SYSCALL_OPEN_X && t != PPME_SYSCALL_OPENAT_2_X &&
		   t != PPME_SYSCALL_OPENAT2_X) {
			return false;
		}
		std::string flags = evt->get_param_value_str("flags");
		bool is_read = flags.find("O_RDONLY") != std::string::npos ||
		               (flags.find("O_WRONLY") == std::string::npos &&
		                flags.find("O_RDWR") == std::string::npos);
		return is_read && child_pid > 0 && evt->get_tid() == child_pid;
	};

	run_callback_t test = [&](sinsp* inspector) {
		child_pid = fork();
		if(child_pid == 0) {
			int fd = syscall(__NR_openat, AT_FDCWD, shadow_path, O_RDONLY | O_CLOEXEC, 0);
			if(fd >= 0) {
				close(fd);
			}
			_exit(0);
		} else {
			waitpid(child_pid, nullptr, 0);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		std::string name = param.m_evt->get_param_value_str("name");
		if(name == shadow_path) {
			std::string fd = param.m_evt->get_param_value_str("fd", false);
			EXPECT_FALSE(fd.empty());
			if(!fd.empty()) {
				EXPECT_NE('-', fd[0]);
			}
			found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(found);
}
