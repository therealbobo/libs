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

#pragma once

#include "subprocess.h"

#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

// RAII wrapper around a detached Docker container.
// Starts the container on construction, stops it on destruction.
class docker_container {
public:
	// image:    Docker image to run (e.g. "nginx:1.14-alpine")
	// args:     extra arguments passed after the image name
	// user:     optional --user value (e.g. "11:100"), empty = container default
	docker_container(const std::string& image,
	                 const std::vector<std::string>& args = {},
	                 const std::string& user = "") {
		std::vector<std::string> docker_args = {"run", "-d", "--rm"};
		if(!user.empty()) {
			docker_args.push_back("--user");
			docker_args.push_back(user);
		}
		docker_args.push_back(image);
		for(const auto& a : args) {
			docker_args.push_back(a);
		}

		subprocess proc("docker", docker_args);
		m_full_id = proc.out();
		proc.wait();

		if(m_full_id.empty()) {
			throw std::runtime_error("docker run returned an empty container ID");
		}

		// Give the container a moment to initialise.
		sleep(2);
	}

	~docker_container() {
		if(!m_full_id.empty()) {
			subprocess("docker", {"stop", m_full_id}).wait();
		}
	}

	// Returns the 12-character prefix used by libsinsp as container.id.
	std::string get_id() const { return m_full_id.substr(0, 12); }

	// Runs a command inside the container and blocks until it exits.
	// If user is non-empty, passes --user <user> to docker exec.
	void exec(const std::vector<std::string>& cmd, const std::string& user = "") {
		std::vector<std::string> docker_args = {"exec"};
		if(!user.empty()) {
			docker_args.push_back("--user");
			docker_args.push_back(user);
		}
		docker_args.push_back(m_full_id);
		docker_args.insert(docker_args.end(), cmd.begin(), cmd.end());
		subprocess("docker", docker_args).wait();
	}

private:
	std::string m_full_id;
};
