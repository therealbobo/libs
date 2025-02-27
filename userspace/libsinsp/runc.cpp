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

#include <libsinsp/runc.h>

#include <cstring>

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

namespace {

const size_t CONTAINER_ID_LENGTH = 64;
const size_t REPORTED_CONTAINER_ID_LENGTH = 12;
const char *CONTAINER_ID_VALID_CHARACTERS = "0123456789abcdefABCDEF";

static_assert(REPORTED_CONTAINER_ID_LENGTH <= CONTAINER_ID_LENGTH,
              "Reported container ID length cannot be longer than actual length");

}  // namespace

namespace libsinsp {
namespace runc {

inline static bool endswith(const std::string &s, const std::string &suffix) {
	return s.rfind(suffix) == (s.size() - suffix.size());
}

// check if cgroup ends with <prefix><container_id><suffix>
// If true, set <container_id> to a truncated version of the id and return true.
// Otherwise return false and leave container_id unchanged
bool match_one_container_id(const std::string &cgroup,
                            const std::string &prefix,
                            const std::string &suffix,
                            std::string &container_id) {
	size_t start_pos = cgroup.rfind(prefix);
	if(start_pos == std::string::npos) {
		return false;
	}
	start_pos += prefix.size();

	size_t end_pos = cgroup.rfind(suffix);
	if(end_pos == std::string::npos) {
		return false;
	}

	if(end_pos - start_pos == CONTAINER_ID_LENGTH &&
	   cgroup.find_first_not_of(CONTAINER_ID_VALID_CHARACTERS, start_pos) >= CONTAINER_ID_LENGTH) {
		container_id = cgroup.substr(start_pos, REPORTED_CONTAINER_ID_LENGTH);
		return true;
	}

	// In some container runtimes the container the container id is not
	// necessarly CONTAINER_ID_LENGTH long and can be arbitrarly defined.
	// To keep it simple we only discard the container id > of CONTAINER_ID_LENGTH.
	if(end_pos - start_pos > CONTAINER_ID_LENGTH || end_pos - start_pos == 0) {
		return false;
	}

	// Avoid system host cgroups.
	if(cgroup.rfind("/default/") == 0 && !endswith(cgroup, ".service") &&
	   !endswith(cgroup, ".slice")) {
		size_t reported_len = end_pos - start_pos >= REPORTED_CONTAINER_ID_LENGTH
		                              ? REPORTED_CONTAINER_ID_LENGTH
		                              : end_pos - start_pos;
		container_id = cgroup.substr(start_pos, reported_len);
		return true;
	}

	return false;
}

bool match_container_id(const std::string &cgroup,
                        const libsinsp::runc::cgroup_layout *layout,
                        std::string &container_id) {
	for(size_t i = 0; layout[i].prefix && layout[i].suffix; ++i) {
		if(match_one_container_id(cgroup, layout[i].prefix, layout[i].suffix, container_id)) {
			return true;
		}
	}

	return false;
}
bool matches_runc_cgroups(const sinsp_threadinfo *tinfo,
                          const cgroup_layout *layout,
                          std::string &container_id,
                          std::string &matching_cgroup) {
	for(const auto &it : tinfo->cgroups()) {
		if(match_container_id(it.second, layout, container_id)) {
			matching_cgroup = it.second;
			return true;
		}
	}

	return false;
}
}  // namespace runc
}  // namespace libsinsp
