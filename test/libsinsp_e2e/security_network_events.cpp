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
//   test_event_generator/test_network_activity.py
//   test_network/test_network.py

#include "event_capture.h"
#include "subprocess.h"
#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// ─────────────────────────────────────────────────────────────────────────────
// test_network_activity.py — SystemProcsNetworkActivity
//
// Open a UDP socket and connect() to 10.2.3.4:8192.  The connect() will fail
// (no route), but libsinsp still records the exit event.
// Expect a PPME_SOCKET_CONNECT_X event whose fd.name tuple contains
// "->10.2.3.4:8192".
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_network_connect) {
	bool connect_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_type() == PPME_SOCKET_CONNECT_X && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) {
		int sock = socket(AF_INET, SOCK_DGRAM, 0);
		if(sock < 0) {
			return;
		}

		struct sockaddr_in dst {};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(8192);
		inet_pton(AF_INET, "10.2.3.4", &dst.sin_addr);

		// connect() on a UDP socket records the peer address without sending.
		connect(sock, reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
		close(sock);
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		std::string fd_name = e->get_param_value_str("fd");
		// The fd.name tuple should include the destination 10.2.3.4:8192.
		if(fd_name.find("10.2.3.4:8192") != std::string::npos && !connect_found) {
			connect_found = true;
			// The tuple field in args also encodes src->dst.
			std::string args = e->get_param_value_str("tuple");
			EXPECT_NE(std::string::npos, args.find("10.2.3.4:8192"));
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(connect_found);
}

// ─────────────────────────────────────────────────────────────────────────────
// test_network.py — test_curl_nginx
//
// Fork a simple TCP server child.  The test thread connects to it.
// Expect:
//   - PPME_SOCKET_SOCKET_X from the test thread (socket creation)
//   - PPME_SOCKET_ACCEPT4_5_X or PPME_SOCKET_ACCEPT4_6_X from the server child
//   - PPME_SYSCALL_CLOSE_X from both sides
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(sys_call_test, security_tcp_socket_events) {
	static const int port = 41234;

	pid_t server_pid = -1;
	bool socket_found = false;
	bool accept_found = false;
	bool client_close_found = false;
	bool server_close_found = false;

	event_filter_t filter = [&](sinsp_evt* evt) {
		if(!PPME_IS_EXIT(evt->get_type())) {
			return false;
		}
		uint16_t t = evt->get_type();
		// Accept events from the test thread (client) and the server child.
		bool from_client = m_tid_filter(evt);
		bool from_server = server_pid > 0 && evt->get_tid() == server_pid;
		if(!from_client && !from_server) {
			return false;
		}
		return t == PPME_SOCKET_SOCKET_X || t == PPME_SOCKET_ACCEPT_X ||
		       t == PPME_SOCKET_ACCEPT_5_X || t == PPME_SOCKET_ACCEPT4_5_X ||
		       t == PPME_SOCKET_ACCEPT4_6_X || t == PPME_SYSCALL_CLOSE_X;
	};

	run_callback_t test = [&](sinsp* inspector) {
		// ── Server child ─────────────────────────────────────────────────────
		server_pid = fork();
		if(server_pid == 0) {
			int srv = socket(AF_INET, SOCK_STREAM, 0);
			int reuse = 1;
			setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

			struct sockaddr_in addr {};
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

			bind(srv, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
			listen(srv, 1);

			int cli = accept(srv, nullptr, nullptr);
			if(cli >= 0) {
				close(cli);
			}
			close(srv);
			_exit(0);
		}

		// ── Client (test thread) ──────────────────────────────────────────────
		// Give the server a moment to listen.
		usleep(200000);

		int sock = socket(AF_INET, SOCK_STREAM, 0);
		if(sock < 0) {
			return;
		}

		struct sockaddr_in dst {};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(port);
		dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		connect(sock, reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
		close(sock);

		waitpid(server_pid, nullptr, 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t t = e->get_type();

		if(t == PPME_SOCKET_SOCKET_X && !socket_found && m_tid_filter(e)) {
			// Verify it's an AF_INET stream socket.
			std::string domain = e->get_param_value_str("domain");
			if(domain.find("AF_INET") != std::string::npos) {
				EXPECT_NE(std::string::npos, domain.find("AF_INET"));
				socket_found = true;
			}
		} else if((t == PPME_SOCKET_ACCEPT_X || t == PPME_SOCKET_ACCEPT_5_X ||
		           t == PPME_SOCKET_ACCEPT4_5_X || t == PPME_SOCKET_ACCEPT4_6_X) &&
		          !accept_found && server_pid > 0 && e->get_tid() == server_pid) {
			accept_found = true;
		} else if(t == PPME_SYSCALL_CLOSE_X) {
			std::string fd_name = e->get_param_value_str("fd");
			// Look for close of a TCP socket fd.
			if(fd_name.find("<4t>") != std::string::npos) {
				if(m_tid_filter(e) && !client_close_found) {
					EXPECT_EQ("0", e->get_param_value_str("res", false));
					client_close_found = true;
				} else if(server_pid > 0 && e->get_tid() == server_pid && !server_close_found) {
					EXPECT_EQ("0", e->get_param_value_str("res", false));
					server_close_found = true;
				}
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_TRUE(socket_found);
	EXPECT_TRUE(accept_found);
	EXPECT_TRUE(client_close_found);
	EXPECT_TRUE(server_close_found);
}
