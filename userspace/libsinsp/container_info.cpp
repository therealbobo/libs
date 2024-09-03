// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libsinsp/container_info.h>
#include <libsinsp/sinsp.h>

std::vector<std::string> sinsp_container_info::container_health_probe::probe_type_names = {
	"None",
	"Healthcheck",
	"LivenessProbe",
	"ReadinessProbe",
	"End"
};

sinsp_container_lookup::sinsp_container_lookup(short max_retry, short max_delay_ms):
	m_max_retry(max_retry),
	m_max_delay_ms(max_delay_ms),
	m_state(state::FAILED),
	m_retry(0)
{
	assert(max_retry >= 0);
	assert(max_delay_ms > 0);
}

sinsp_container_lookup::state sinsp_container_lookup::get_status() const
{
	return m_state;
}

void sinsp_container_lookup::set_status(state s)
{
	m_state = s;
}

bool sinsp_container_lookup::is_successful() const
{
	return m_state == sinsp_container_lookup::state::SUCCESSFUL;
}

bool sinsp_container_lookup::should_retry() const
{
	if(is_successful())
	{
		return false;
	}

	return m_retry < m_max_retry;
}

/**
	* i.e. whether we didn't do any retry yet
	*/
bool sinsp_container_lookup::first_attempt() const
{
	return m_retry == 0;
}

short sinsp_container_lookup::retry_no() const
{
	return m_retry;
}

void sinsp_container_lookup::attempt_increment()
{
	++m_retry;
}

/**
	* Compute the delay and increment retry count
	*/
short sinsp_container_lookup::delay()
{
	int curr_delay = 125 << (m_retry-1);
	return curr_delay > m_max_delay_ms ? m_max_delay_ms : curr_delay;
}

// Initialize container max label length to default 100 value
uint32_t sinsp_container_info::m_container_label_max_length = 100;

sinsp_container_info::container_health_probe::container_health_probe()
{
}

sinsp_container_info::container_health_probe::container_health_probe(const probe_type ptype,
								     const std::string &&exe,
								     const std::vector<std::string> &&args)
	: m_probe_type(ptype),
	  m_health_probe_exe(exe),
	  m_health_probe_args(args)
{
}

sinsp_container_info::container_health_probe::~container_health_probe()
{
}

void sinsp_container_info::container_health_probe::parse_health_probes(const Json::Value &config_obj,
								       std::list<container_health_probe> &probes)
{
	// Add any health checks described in the container config/labels.
	for(int i=PT_NONE; i != PT_END; i++)
	{
		std::string key = probe_type_names[i];
		const Json::Value& probe_obj = config_obj[key];

		if(!probe_obj.isNull() && probe_obj.isObject())
		{
			const Json::Value& probe_exe_obj = probe_obj["exe"];

			if(!probe_exe_obj.isNull() && probe_exe_obj.isConvertibleTo(Json::stringValue))
			{
				const Json::Value& probe_args_obj = probe_obj["args"];

				std::string probe_exe = probe_exe_obj.asString();
				std::vector<std::string> probe_args;

				if(!probe_args_obj.isNull() && probe_args_obj.isArray())
				{
					for(const auto &item : probe_args_obj)
					{
						if(item.isConvertibleTo(Json::stringValue))
						{
							probe_args.push_back(item.asString());
						}
					}
				}
				libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
						"add_health_probes: adding %s %s %d",
						probe_type_names[i].c_str(),
						probe_exe.c_str(),
						probe_args.size());

				probes.emplace_back(static_cast<probe_type>(i), std::move(probe_exe), std::move(probe_args));
			}
		}
	}
}

void sinsp_container_info::container_health_probe::add_health_probes(const std::list<container_health_probe> &probes,
								     Json::Value &config_obj)
{
	for(auto &probe : probes)
	{
		std::string key = probe_type_names[probe.m_probe_type];
		Json::Value args;

		config_obj[key]["exe"] = probe.m_health_probe_exe;
		for(auto &arg : probe.m_health_probe_args)
		{
			args.append(arg);
		}

		config_obj[key]["args"] = args;
	}
}

sinsp_container_info::container_port_mapping::container_port_mapping():
	m_host_ip(0),
	m_host_port(0),
	m_container_port(0)
{
}

sinsp_container_info::container_mount_info::container_mount_info():
	m_source(""),
	m_dest(""),
	m_mode(""),
	m_rdwr(false),
	m_propagation("")
{
}

sinsp_container_info::container_mount_info::container_mount_info(const std::string&& source, const std::string&& dest,
				const std::string&& mode, const bool rw,
				const std::string&& propagation) :
	m_source(source), m_dest(dest), m_mode(mode), m_rdwr(rw), m_propagation(propagation)
{
}

sinsp_container_info::container_mount_info::container_mount_info(const Json::Value &source, const Json::Value &dest,
				const Json::Value &mode, const Json::Value &rw,
				const Json::Value &propagation)
{
	get_string_value(source, m_source);
	get_string_value(dest, m_dest);
	get_string_value(mode, m_mode);
	get_string_value(propagation, m_propagation);

	if(!rw.isNull() && rw.isBool())
	{
		m_rdwr = rw.asBool();
	}
}


std::string sinsp_container_info::container_mount_info::to_string() const
{
	return m_source + ":" +
			m_dest + ":" +
			m_mode + ":" +
			(m_rdwr ? "true" : "false") + ":" +
			m_propagation;
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_idx(uint32_t idx) const
{
	if (idx >= m_mounts.size())
	{
		return NULL;
	}

	return &(m_mounts[idx]);
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_source(const std::string& source) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(source.c_str(), mntinfo.m_source.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_dest(const std::string& dest) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(dest.c_str(), mntinfo.m_dest.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

std::unique_ptr<sinsp_threadinfo> sinsp_container_info::get_tinfo(sinsp* inspector) const
{
	auto tinfo = inspector->build_threadinfo();
	tinfo->m_tid = -1;
	tinfo->m_pid = -1;
	tinfo->m_vtid = -2;
	tinfo->m_vpid = -2;
	tinfo->m_comm = "container:" + m_id;
	tinfo->m_exe = "container:" + m_id;
	tinfo->m_container_id = m_id;
	return tinfo;
}

sinsp_container_info::container_health_probe::probe_type sinsp_container_info::match_health_probe(sinsp_threadinfo *tinfo) const
{
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"match_health_probe (%s): %u health probes to consider",
			m_id.c_str(), m_health_probes.size());

	auto pred = [&] (const container_health_probe &p) {
                libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"match_health_probe (%s): Matching tinfo %s %d against %s %d",
				m_id.c_str(),
				tinfo->m_exe.c_str(), tinfo->m_args.size(),
				p.m_health_probe_exe.c_str(), p.m_health_probe_args.size());

                return (p.m_health_probe_exe == tinfo->m_exe &&
			p.m_health_probe_args == tinfo->m_args);
        };

	auto match = std::find_if(m_health_probes.begin(),
				  m_health_probes.end(),
				  pred);

	if(match == m_health_probes.end())
	{
		return container_health_probe::PT_NONE;
	}

	return match->m_probe_type;
}

sinsp_container_info::sinsp_container_info(sinsp_container_lookup &&lookup):
	m_type(CT_UNKNOWN),
	m_container_ip(0),
	m_privileged(false),
	m_memory_limit(0),
	m_swap_limit(0),
	m_cpu_shares(1024),
	m_cpu_quota(0),
	m_cpu_period(100000),
	m_cpuset_cpu_count(0),
	m_is_pod_sandbox(false),
	m_lookup(std::move(lookup)),
	m_container_user("<NA>"),
	m_metadata_deadline(0),
	m_size_rw_bytes(-1)
{
}

void sinsp_container_info::clear()
{
	this->~sinsp_container_info();
	new(this) sinsp_container_info();
}

const std::vector<std::string>& sinsp_container_info::get_env() const
{
	return m_env;
}

bool sinsp_container_info::is_pod_sandbox() const
{
	return m_is_pod_sandbox;
}

bool sinsp_container_info::is_successful() const
{
	return m_lookup.is_successful();
}

void sinsp_container_info::set_lookup_status(sinsp_container_lookup::state s)
{
	m_lookup.set_status(s);
}

sinsp_container_lookup::state sinsp_container_info::get_lookup_status() const
{
	return m_lookup.get_status();
}
