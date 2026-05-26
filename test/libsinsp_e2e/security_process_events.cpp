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

// Ports of the Python e2e tests in test/e2e/tests/:
//   test_event_generator/test_non_sudo_setuid.py
//   test_event_generator/test_db_program_spawned_process.py
//   test_event_generator/test_system_user_interactive.py
//   test_event_generator/test_run_shell_untrusted.py
//   test_process/test_container.py  (test_exec_in_container, test_container_root_user)

#include "docker_utils.h"
#include "event_capture.h"
#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <string>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// ─────────────────────────────────────────────────────────────────────────────
// test_non_sudo_setuid.py — NonSudoSetuid
//
// Fork a child that calls setuid(2) (succeeds when running as root), then
// setuid(0) (fails EPERM because effective uid is now 2).
// Expect two PPME_SYSCALL_SETUID_X events from the child.
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_non_sudo_setuid) {
	if(getuid() != 0) {
		GTEST_SKIP() << "requires root";
	}

	pid_t child_pid = -1;
	bool setuid_success_found = false;
	bool setuid_fail_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_type() == PPME_SYSCALL_SETUID_X && child_pid > 0 &&
		       evt->get_tid() == child_pid;
	};

	run_callback_t test = [&](sinsp* inspector) {
		child_pid = fork();
		if(child_pid == 0) {
			// setuid(2): should succeed (we're root)
			(void)setuid(2);
			// setuid(0): should fail with EPERM (we're now uid 2)
			(void)setuid(0);
			_exit(0);
		} else {
			waitpid(child_pid, nullptr, 0);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		std::string uid = e->get_param_value_str("uid", false);
		std::string res = e->get_param_value_str("res", false);

		if(uid == "2" && !setuid_success_found) {
			EXPECT_EQ("0", res);
			setuid_success_found = true;
		} else if(uid == "0" && setuid_success_found && !setuid_fail_found) {
			// -1 means EPERM
			EXPECT_EQ("-1", res);
			setuid_fail_found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(setuid_success_found);
	EXPECT_TRUE(setuid_fail_found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_db_program_spawned_process.py — DbProgramSpawnedProcess
//
// Fork an intermediate process ("mysqld") which forks-execs /bin/ls.
// Expect a clone exit from the intermediate and an execve exit from ls.
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_db_program_spawned_process) {
	pid_t intermediate_pid = -1;
	bool clone_found = false;
	bool execve_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		if(!PPME_IS_EXIT(evt->get_type())) {
			return false;
		}
		uint16_t t = evt->get_type();
		if(t == PPME_SYSCALL_CLONE_20_X || t == PPME_SYSCALL_CLONE3_X) {
			return intermediate_pid > 0 && evt->get_tid() == intermediate_pid;
		}
		if(t == PPME_SYSCALL_EXECVE_19_X) {
			// Accept the execve from the grandchild (ls).
			auto ti = evt->get_thread_info();
			return ti && ti->m_comm == "ls";
		}
		return false;
	};

	run_callback_t test = [&](sinsp* inspector) {
		intermediate_pid = fork();
		if(intermediate_pid == 0) {
			// Intermediate process: fork and exec /bin/ls.
			pid_t ls_pid = fork();
			if(ls_pid == 0) {
				execl("/bin/ls", "ls", nullptr);
				_exit(1);
			}
			waitpid(ls_pid, nullptr, 0);
			_exit(0);
		} else {
			waitpid(intermediate_pid, nullptr, 0);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t t = e->get_type();
		if((t == PPME_SYSCALL_CLONE_20_X || t == PPME_SYSCALL_CLONE3_X) && !clone_found) {
			// Clone result in the parent is the child PID (> 0).
			std::string res = e->get_param_value_str("res", false);
			if(!res.empty() && res != "0" && res[0] != '-') {
				clone_found = true;
			}
		} else if(t == PPME_SYSCALL_EXECVE_19_X && !execve_found) {
			// "exe" is argv[0]; execl("/bin/ls", "ls", nullptr) sets argv[0]="ls".
			std::string exe = e->get_param_value_str("exe");
			EXPECT_EQ("ls", exe);
			execve_found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(clone_found);
	EXPECT_TRUE(execve_found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_system_user_interactive.py — SystemUserInteractive
//
// Fork a child that exec-s /bin/login.
// Expect a PPME_SYSCALL_EXECVE_19_X event with exe=/bin/login.
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_system_user_interactive) {
	if(access("/bin/login", X_OK) != 0) {
		GTEST_SKIP() << "/bin/login not executable";
	}

	pid_t child_pid = -1;
	bool execve_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_type() == PPME_SYSCALL_EXECVE_19_X && child_pid > 0 &&
		       evt->get_tid() == child_pid;
	};

	run_callback_t test = [&](sinsp* inspector) {
		child_pid = fork();
		if(child_pid == 0) {
			// Redirect stdin/stdout/stderr to /dev/null so login fails fast.
			int dev_null = open("/dev/null", O_RDWR);
			if(dev_null >= 0) {
				dup2(dev_null, STDIN_FILENO);
				dup2(dev_null, STDOUT_FILENO);
				dup2(dev_null, STDERR_FILENO);
				close(dev_null);
			}
			execl("/bin/login", "login", nullptr);
			_exit(1);
		} else {
			waitpid(child_pid, nullptr, 0);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		// "exe" is argv[0]; execl("/bin/login", "login", nullptr) sets argv[0]="login".
		std::string exe = e->get_param_value_str("exe");
		if(exe == "login" && !execve_found) {
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			execve_found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(execve_found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_run_shell_untrusted.py — RunShellUntrusted
//
// Fork a child that exec-s sh, which then exec-s bash (two-step chain).
// Both execve events share the same TID (exec replaces the process image in
// place), mirroring the Python test's two-event sequence: intermediate process
// (httpd) → bash.
// Expect two PPME_SYSCALL_EXECVE_19_X events: exe=sh then exe=bash.
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_run_shell_untrusted) {
	pid_t child_pid = -1;
	bool sh_execve_found = false;
	bool bash_execve_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_type() == PPME_SYSCALL_EXECVE_19_X && child_pid > 0 &&
		       evt->get_tid() == child_pid;
	};

	run_callback_t test = [&](sinsp* inspector) {
		child_pid = fork();
		if(child_pid == 0) {
			execl("/bin/sh", "sh", "-c", "exec bash -c 'ls > /dev/null'", nullptr);
			_exit(1);
		} else {
			waitpid(child_pid, nullptr, 0);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		std::string exe = e->get_param_value_str("exe");
		if(exe == "sh" && !sh_execve_found) {
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			sh_execve_found = true;
		} else if(exe == "bash" && !bash_execve_found) {
			// sh searches PATH and emits failed execve events (res=-ENOENT) for
			// each candidate path before finding bash; only latch on success.
			if(e->get_param_value_str("res", false) == "0") {
				bash_execve_found = true;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(sh_execve_found);
	EXPECT_TRUE(bash_execve_found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_container.py — test_exec_in_container
//
// Run hashicorp/http-echo:alpine as user 11:100, exec sleep and sh inside.
// Expect execve events with user.uid=11 and group.gid=100.
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_exec_in_container) {
	// Probe that docker is reachable before starting capture.
	if(system("docker info > /dev/null 2>&1") != 0) {
		GTEST_SKIP() << "docker not available";
	}

	bool http_echo_found = false;
	bool sleep_found = false;
	bool sh_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		if(evt->get_type() != PPME_SYSCALL_EXECVE_19_X) {
			return false;
		}
		auto ti = evt->get_thread_info();
		return ti && ti->m_uid == 11 && ti->m_gid == 100;
	};

	// Start the container inside the capture window so its initial execve is recorded.
	run_callback_t test = [&](sinsp* inspector) {
		docker_container container("hashicorp/http-echo:alpine", {"-text=hello"}, "11:100");
		container.exec({"sleep", "1"});
		container.exec({"sh", "-c", "ls"});
		// destructor stops the container
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		auto ti = e->get_thread_info();
		if(!ti) {
			return;
		}

		EXPECT_EQ(11u, ti->m_uid);
		EXPECT_EQ(100u, ti->m_gid);

		std::string comm = ti->m_comm;
		if(comm.find("http-echo") != std::string::npos && !http_echo_found) {
			http_echo_found = true;
		} else if(comm == "sleep" && !sleep_found) {
			sleep_found = true;
		} else if(comm == "sh" && !sh_found) {
			sh_found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(http_echo_found);
	EXPECT_TRUE(sleep_found);
	EXPECT_TRUE(sh_found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_container.py — test_container_root_user
//
// Run nginx:1.14-alpine (starts as root), then exec sh as the nginx user.
// Expect execve events for nginx (uid=0) and sh (uid=nginx).
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_container_root_user) {
	if(system("docker info > /dev/null 2>&1") != 0) {
		GTEST_SKIP() << "docker not available";
	}

	bool nginx_root_found = false;
	bool sh_nginx_found = false;

	// nginx master starts as root (uid=0). When we exec sh as user "nginx"
	// it runs with the nginx uid.
	event_filter_t filter = [&](sinsp_evt* evt) {
		if(evt->get_type() != PPME_SYSCALL_EXECVE_19_X) {
			return false;
		}
		auto ti = evt->get_thread_info();
		if(!ti) {
			return false;
		}
		std::string comm = ti->m_comm;
		return comm == "nginx" || comm == "sh";
	};

	// Start the container inside the capture window so its initial execve is recorded.
	run_callback_t test = [&](sinsp* inspector) {
		docker_container container("nginx:1.14-alpine");
		// exec sh as the nginx user (non-root uid)
		container.exec({"sh", "-c", "ls"}, "nginx");
		// destructor stops the container
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		auto ti = e->get_thread_info();
		if(!ti) {
			return;
		}
		std::string comm = ti->m_comm;

		if(comm == "nginx" && !nginx_root_found) {
			EXPECT_EQ(0u, ti->m_uid);
			EXPECT_EQ(0u, ti->m_gid);
			nginx_root_found = true;
		} else if(comm == "sh" && !sh_nginx_found) {
			// nginx user has a non-zero uid; just verify it is captured and non-root.
			EXPECT_GT(ti->m_uid, 0u);
			sh_nginx_found = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(nginx_root_found);
	EXPECT_TRUE(sh_nginx_found);
}
