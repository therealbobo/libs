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

#include <libsinsp/container_engine/libvirt_lxc.h>
#include <libsinsp/sinsp.h>

using namespace libsinsp::container_engine;

bool libvirt_lxc::match(sinsp_threadinfo* tinfo, sinsp_container_info& container_info) {
	for(const auto& it : tinfo->cgroups()) {
		//
		// Non-systemd libvirt-lxc
		//
		const auto& cgroup = it.second;
		size_t pos = cgroup.find(".libvirt-lxc");
		if(pos != std::string::npos && pos == cgroup.length() - sizeof(".libvirt-lxc") + 1) {
			size_t pos2 = cgroup.find_last_of("/");
			if(pos2 != std::string::npos) {
				container_info.m_type = CT_LIBVIRT_LXC;
				container_info.m_id = cgroup.substr(pos2 + 1, pos - pos2 - 1);
				return true;
			}
		}

		//
		// systemd libvirt-lxc:
		//
		pos = cgroup.find("-lxc\\x2");
		if(pos != std::string::npos) {
			// For cgroups like:
			// /machine.slice/machine-lxc\x2d2293906\x2dlibvirt\x2dcontainer.scope/libvirt,
			// account for /libvirt below.
			std::string delimiter = (cgroup.find(".scope/libvirt") != std::string::npos)
			                                ? ".scope/libvirt"
			                                : ".scope";
			size_t pos2 = cgroup.find(delimiter);
			if(pos2 != std::string::npos && pos2 == cgroup.length() - delimiter.length()) {
				container_info.m_type = CT_LIBVIRT_LXC;
				container_info.m_id =
				        cgroup.substr(pos + sizeof("-lxc\\x2"), pos2 - pos - sizeof("-lxc\\x2"));
				return true;
			}
		}

		//
		// Legacy libvirt-lxc
		//
		pos = cgroup.find("/libvirt/lxc/");
		if(pos != std::string::npos) {
			container_info.m_type = CT_LIBVIRT_LXC;
			container_info.m_id = cgroup.substr(pos + sizeof("/libvirt/lxc/") - 1);
			return true;
		}
	}
	return false;
}

bool libvirt_lxc::resolve(sinsp_threadinfo* tinfo, bool query_os_for_missing_info) {
	auto container = sinsp_container_info();

	if(!match(tinfo, container)) {
		return false;
	}

	tinfo->m_container_id = container.m_id;
	if(container_cache().should_lookup(container.m_id, CT_LIBVIRT_LXC)) {
		container.m_name = container.m_id;
		container.set_lookup_status(sinsp_container_lookup::state::SUCCESSFUL);
		container_cache().add_container(std::make_shared<sinsp_container_info>(container), tinfo);
		container_cache().notify_new_container(container, tinfo);
	}
	return true;
}
