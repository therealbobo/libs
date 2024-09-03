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

#include <libsinsp/cri.hpp>

namespace libsinsp
{
namespace cri
{

cri_settings::cri_settings():
	m_cri_unix_socket_paths(),
	m_cri_timeout(1000),
	m_cri_size_timeout(10000),
	m_cri_runtime_type(CT_CRI),
	m_cri_unix_socket_path(),
	m_cri_extra_queries(true)
{ }

cri_settings::~cri_settings()
{ }

std::unique_ptr<cri_settings> cri_settings::s_instance = nullptr;

cri_settings& cri_settings::get()
{
	if(s_instance == nullptr)
	{
		s_instance = std::make_unique<cri_settings>();
	}
	return *s_instance;
}

const std::vector<std::string>& cri_settings::get_cri_unix_socket_paths()
{
	return get().m_cri_unix_socket_paths;
}

void cri_settings::set_cri_unix_socket_paths(const std::vector<std::string>& v)
{
	get().m_cri_unix_socket_paths = v;
}

const int64_t& cri_settings::get_cri_timeout()
{
	return get().m_cri_timeout;
}

void cri_settings::set_cri_timeout(const int64_t& v)
{
	get().m_cri_timeout = v;
}

const int64_t& cri_settings::get_cri_size_timeout()
{
	return get().m_cri_size_timeout;
}

void cri_settings::set_cri_size_timeout(const int64_t& v)
{
	get().m_cri_size_timeout = v;
}

const sinsp_container_type& cri_settings::get_cri_runtime_type()
{
	return get().m_cri_runtime_type;
}

void cri_settings::set_cri_runtime_type(const sinsp_container_type& v)
{
	get().m_cri_runtime_type = v;
}

const std::string& cri_settings::get_cri_unix_socket_path()
{
	return get().m_cri_unix_socket_path;
}

void cri_settings::set_cri_unix_socket_path(const std::string& v)
{
	get().m_cri_unix_socket_path = v;
}

const bool& cri_settings::get_cri_extra_queries()
{
	return get().m_cri_extra_queries;
}

void cri_settings::set_cri_extra_queries(const bool& v)
{
	get().m_cri_extra_queries = v;
}

void cri_settings::add_cri_unix_socket_path(const std::string& v)
{
	get().m_cri_unix_socket_paths.emplace_back(v);
}

void cri_settings::clear_cri_unix_socket_paths()
{
	get().m_cri_unix_socket_paths.clear();
}

} // namespace cri
} // namespace libsinsp
