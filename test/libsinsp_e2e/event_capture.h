// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#pragma once

#include "libsinsp_test_var.h"
#include "event_thread.h"

#include <gtest/gtest.h>

#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <libsinsp/sinsp.h>

#include <functional>
#include <mutex>
#include <stdexcept>

typedef std::function<bool(sinsp_evt* evt)> event_filter_t;

class event_capture
{
public:
	void init_inspector();

	static sinsp* get_inspector()
	{
			static sinsp inspector = sinsp();
			return &inspector;
	}

	event_capture(event_filter_t filter, event_thread& test_thread,
				  pid_t tid = -1, uint32_t max_thread_table_size = 131072,
				  uint64_t thread_timeout_ns = (uint64_t)60 * 1000 * 1000 * 1000,
				  uint64_t inactive_thread_scan_time_ns = (uint64_t)60 * 1000 * 1000 * 1000,
				  sinsp_mode_t mode = SINSP_MODE_LIVE, uint64_t max_timeouts = 3);
	virtual ~event_capture();
	void start();
	size_t stop();
	void disable_tid_filter(bool v);
	void use_subprocess(bool v);

	static size_t get_matched_num();
	static void set_engine(const std::string& engine_string, const std::string& engine_path);
	static const std::string& get_engine();
	static void set_buffer_dim(const unsigned long& dim);
	static const std::string& get_engine_path();
	static std::string m_engine_string;
	static std::string m_engine_path;
	static unsigned long m_buffer_dim;

private:

	bool filter(sinsp_evt* event);
	bool handle_event(sinsp_evt* event);

	void open_engine(const std::string& engine_string, libsinsp::events::set<ppm_sc_code> events_sc_codes);

	std::atomic<bool> m_done;
	event_filter_t m_filter;
	std::unique_ptr<sinsp_filter> m_subprocess_filter;
	bool m_use_subprocess;
	uint64_t m_inactive_thread_scan_time_ns;
	uint32_t m_max_thread_table_size;
	uint64_t m_max_timeouts;
	sinsp_mode_t m_mode;
	event_thread& m_test_thread;
	uint64_t m_thread_timeout_ns;
	pid_t m_tid;
	std::string m_start_failure_message;
	bool m_disable_tid_filter;

	static bool s_inspector_ok;
	static size_t s_res_events;
};
