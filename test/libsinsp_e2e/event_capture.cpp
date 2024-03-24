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

#include "event_capture.h"

#include <cstdlib>
#include <gtest/gtest.h>

#include <libsinsp/sinsp.h>
#include <libscap/scap_engines.h>
#include <libsinsp/sinsp_cycledumper.h>
#include <unistd.h>

std::string event_capture::m_engine_string = KMOD_ENGINE;
std::string event_capture::m_engine_path = "";
unsigned long event_capture::m_buffer_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;
bool event_capture::s_inspector_ok = false;
size_t event_capture::s_res_events;

event_capture::event_capture(event_filter_t filter, event_thread& test_thread,
							 pid_t tid, uint32_t max_thread_table_size,
							 uint64_t thread_timeout_ns,
							 uint64_t inactive_thread_scan_time_ns,
							 sinsp_mode_t mode, uint64_t max_timeouts):
	m_done(false),
	m_filter(filter),
	m_inactive_thread_scan_time_ns(inactive_thread_scan_time_ns),
	m_max_thread_table_size(max_thread_table_size),
	m_max_timeouts(max_timeouts),
	m_mode(mode),
	m_test_thread(test_thread),
	m_thread_timeout_ns(thread_timeout_ns),
	m_tid(tid),
	m_disable_tid_filter(false)
{
	if(tid == -1)
	{
		m_tid = test_thread.get_tid();
	}
};

event_capture::~event_capture()
{
	s_res_events = 0;
}

void event_capture::init_inspector()
{
		get_inspector()->m_thread_manager->set_max_thread_table_size(m_max_thread_table_size);
		get_inspector()->m_thread_timeout_ns = m_thread_timeout_ns;
		get_inspector()->set_auto_threads_purging_interval_s(m_inactive_thread_scan_time_ns);
		get_inspector()->set_auto_threads_purging(false);

		get_inspector()->set_get_procs_cpu_from_driver(true);

		ASSERT_FALSE(get_inspector()->is_capture());
		ASSERT_FALSE(get_inspector()->is_live());
		ASSERT_FALSE(get_inspector()->is_nodriver());

		try
		{
			open_engine(event_capture::get_engine(), {});
		}
		catch (sinsp_exception& e)
		{
			m_start_failure_message =
				"couldn't open inspector (maybe driver hasn't been loaded yet?) err=" +
				get_inspector()->getlasterr() + " exception=" + e.what();
			return;
		}

		get_inspector()->set_debug_mode(true);
		get_inspector()->set_hostname_and_port_resolution_mode(false);
}

size_t event_capture::stop()
{
	return s_res_events;
}

void event_capture::start()
{
	const ::testing::TestInfo* const test_info =
		::testing::UnitTest::GetInstance()->current_test_info();
	std::unique_ptr<sinsp_cycledumper> dumper;
	std::string dump_filename;
	int32_t next_result = SCAP_SUCCESS;
	uint32_t n_timeouts = 0;

	if(!s_inspector_ok)
	{
		init_inspector();
		s_inspector_ok = true;
	}

	dump_filename = std::string(LIBSINSP_TEST_CAPTURES_PATH) + test_info->test_case_name() + "_" +
		test_info->name() + ".scap";
	dumper = std::make_unique<sinsp_cycledumper>(get_inspector(), dump_filename.c_str(),
													0, 0, 0, 0, true);

	std::thread inspector_thread([&]{
		sinsp_evt* event;

		get_inspector()->start_capture();

		m_test_thread.start();

		while (!m_done)
		{
			next_result = get_inspector()->next(&event);
			switch(next_result)
			{
				case SCAP_SUCCESS:
					dumper->dump(event);
					handle_event(event);
					break;
				case SCAP_TIMEOUT:
					n_timeouts++;
					if (n_timeouts >= m_max_timeouts)
					{
						m_done = true;
					}
					break;
				default:
					break;
			}
		}

		get_inspector()->stop_capture();

		while (SCAP_SUCCESS == get_inspector()->next(&event))
		{
			// just consume the remaining events
			//dumper->dump(event);
		}

	});

	m_test_thread.join();
	inspector_thread.join();
}

bool event_capture::handle_event(sinsp_evt* event)
{
	if((event->get_type() == PPME_GENERIC_E ||
	    event->get_type() == PPME_GENERIC_X) &&
	   event->get_param(0)->as<int16_t>() == 1337)
	{
		m_done = true;
		return false;
	}
	else if ((!m_disable_tid_filter && event->get_tid() == m_tid) && m_filter(event))
	{
		s_res_events++;
		return true;
	}
	return false;
}

void event_capture::open_engine(const std::string& engine_string, libsinsp::events::set<ppm_sc_code> events_sc_codes)
{
	if(false)
	{
	}
#ifdef HAS_ENGINE_KMOD
	else if(!engine_string.compare(KMOD_ENGINE))
	{
		get_inspector()->open_kmod(m_buffer_dim);
	}
#endif
#ifdef HAS_ENGINE_BPF
	else if(!engine_string.compare(BPF_ENGINE))
	{
		if(event_capture::get_engine().empty())
		{
			std::cerr << "You must specify the path to the bpf probe if you use the 'bpf' engine" << std::endl;
			exit(EXIT_FAILURE);
		}
		get_inspector()->open_bpf(event_capture::get_engine_path().c_str(), m_buffer_dim);
	}
#endif
#ifdef HAS_ENGINE_MODERN_BPF
	else if(!engine_string.compare(MODERN_BPF_ENGINE))
	{
		get_inspector()->open_modern_bpf(m_buffer_dim);
	}
#endif
	else
	{
		std::cerr << "Unknown engine" << std::endl;
		exit(EXIT_FAILURE);
	}
}

size_t event_capture::get_matched_num()
{
	return s_res_events;
}

void event_capture::set_engine(const std::string& engine_string, const std::string& engine_path)
{
	m_engine_string = engine_string;
	m_engine_path = engine_path;
}

void event_capture::set_buffer_dim(const unsigned long& dim)
{
	m_buffer_dim = dim;
}

const std::string& event_capture::get_engine()
{
	return m_engine_string;
}

const std::string& event_capture::get_engine_path()
{
	return m_engine_path;
}

void event_capture::disable_tid_filter(bool v)
{
	m_disable_tid_filter = v;
}
