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

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <driver/ppm_events_public.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/filter_cache.h>
#include <libsinsp/base64.h>

enum filter_transformer_type : uint8_t {
	FTR_TOUPPER = 0,
	FTR_TOLOWER = 1,
	FTR_BASE64 = 2,
	FTR_STORAGE = 3,  // This transformer is only used internally
	FTR_BASENAME = 4,
};

static inline std::string filter_transformer_type_str(filter_transformer_type m) {
	switch(m) {
	case FTR_TOUPPER:
		return "toupper";
	case FTR_TOLOWER:
		return "tolower";
	case FTR_BASE64:
		return "b64";
	case FTR_STORAGE:
		return "storage";
	case FTR_BASENAME:
		return "basename";
	default:
		throw sinsp_exception("unknown field transfomer id " + std::to_string(m));
	}
}

static inline filter_transformer_type filter_transformer_from_str(const std::string& str) {
	if(str == "tolower") {
		return filter_transformer_type::FTR_TOLOWER;
	}
	if(str == "toupper") {
		return filter_transformer_type::FTR_TOUPPER;
	}
	if(str == "b64") {
		return filter_transformer_type::FTR_BASE64;
	}
	if(str == "storage") {
		return filter_transformer_type::FTR_STORAGE;
	}
	if(str == "basename") {
		return filter_transformer_type::FTR_BASENAME;
	}
	throw sinsp_exception("unknown field transfomer '" + str + "'");
}

static void throw_unsupported_err(filter_transformer_type t) {
	throw sinsp_exception("transformer '" + std::to_string(t) + "' is not supported");
}

static void throw_type_incompatibility_err(ppm_param_type t, const std::string& trname) {
	throw sinsp_exception("field type '" + std::to_string(t) + "' is not supported by '" + trname +
	                      "' transformer");
}

class sinsp_filter_transformer {
public:
	using storage_t = std::vector<uint8_t>;

	sinsp_filter_transformer() = default;
	virtual ~sinsp_filter_transformer();

	virtual bool transform_type(ppm_param_type& t) const {
		throw_unsupported_err(m_type);
		return false;
	}

	virtual bool transform_values(std::vector<extract_value_t>& vec, ppm_param_type& t) = 0;

protected:
	using str_transformer_func_t = std::function<bool(std::string_view in, storage_t& out)>;

	bool string_transformer(std::vector<extract_value_t>& vec,
	                        ppm_param_type t,
	                        str_transformer_func_t mod);

	filter_transformer_type m_type;
	std::vector<storage_t> m_storage_values;
};

class sinsp_filter_toupper_transformer : public sinsp_filter_transformer {
public:
	using storage_t = std::vector<uint8_t>;

	sinsp_filter_toupper_transformer() { m_type = FTR_TOUPPER; };
	virtual ~sinsp_filter_toupper_transformer() = default;

	bool transform_type(ppm_param_type& t) const override {
		switch(t) {
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			// for TOUPPER, the transformed type is the same as the input type
			return true;
		default:
			return false;
		}
	}

	bool transform_values(std::vector<extract_value_t>& vec, ppm_param_type& t) override {
		if(!transform_type(t)) {
			throw_type_incompatibility_err(t, filter_transformer_type_str(m_type));
		}

		return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
			for(auto c : in) {
				out.push_back(toupper(c));
			}
			return true;
		});
	}
};

class sinsp_filter_tolower_transformer : public sinsp_filter_transformer {
public:
	using storage_t = std::vector<uint8_t>;

	sinsp_filter_tolower_transformer() { m_type = FTR_TOLOWER; };
	virtual ~sinsp_filter_tolower_transformer() = default;

	bool transform_type(ppm_param_type& t) const override {
		switch(t) {
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			// for TOLOWER, the transformed type is the same as the input type
			return true;
		default:
			return false;
		}
	}

	bool transform_values(std::vector<extract_value_t>& vec, ppm_param_type& t) override {
		if(!transform_type(t)) {
			throw_type_incompatibility_err(t, filter_transformer_type_str(m_type));
		}

		return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
			for(auto c : in) {
				out.push_back(tolower(c));
			}
			return true;
		});
	}
};

class sinsp_filter_base64_transformer : public sinsp_filter_transformer {
public:
	using storage_t = std::vector<uint8_t>;

	sinsp_filter_base64_transformer() { m_type = FTR_BASE64; }
	virtual ~sinsp_filter_base64_transformer() = default;

	bool transform_type(ppm_param_type& t) const override {
		switch(t) {
		case PT_CHARBUF:
		case PT_BYTEBUF:
			// for BASE64, the transformed type is the same as the input type
			return true;
		default:
			return false;
		}
	}

	bool transform_values(std::vector<extract_value_t>& vec, ppm_param_type& t) override {
		if(!transform_type(t)) {
			throw_type_incompatibility_err(t, filter_transformer_type_str(m_type));
		}

		return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
			return Base64::decodeWithoutPadding(in, out);
		});
	}
};

class sinsp_filter_storage_transformer : public sinsp_filter_transformer {
public:
	using storage_t = std::vector<uint8_t>;

	sinsp_filter_storage_transformer() { m_type = FTR_STORAGE; };
	virtual ~sinsp_filter_storage_transformer() = default;

	bool transform_type(ppm_param_type& t) const override { return true; }

	bool transform_values(std::vector<extract_value_t>& vec, ppm_param_type& t) override {
		// note: for STORAGE, the transformed type is the same as the input type
		m_storage_values.resize(vec.size());
		for(std::size_t i = 0; i < vec.size(); i++) {
			storage_t& buf = m_storage_values[i];

			buf.clear();
			if(vec[i].ptr == nullptr) {
				continue;
			}

			// We reserve one extra chat for the null terminator
			buf.resize(vec[i].len + 1);
			memcpy(&(buf[0]), vec[i].ptr, vec[i].len);
			// We put the string terminator in any case
			buf[vec[i].len] = '\0';
			vec[i].ptr = &(buf[0]);
			// `vec[i].len` is the same as before
		}
		return true;
	}
};

class sinsp_filter_basename_transformer : public sinsp_filter_transformer {
public:
	using storage_t = std::vector<uint8_t>;

	sinsp_filter_basename_transformer() { m_type = FTR_BASENAME; };
	virtual ~sinsp_filter_basename_transformer() = default;

	bool transform_type(ppm_param_type& t) const override {
		switch(t) {
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			// for BASENAME, the transformed type is the same as the input type
			return true;
		default:
			return false;
		}
	}

	bool transform_values(std::vector<extract_value_t>& vec, ppm_param_type& t) override {
		return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
			auto last_slash_pos = in.find_last_of("/");
			std::string_view::size_type start_idx =
			        last_slash_pos == std::string_view::npos ? 0 : last_slash_pos + 1;

			for(std::string_view::size_type i = start_idx; i < in.length(); i++) {
				out.push_back(in[i]);
			}

			return true;
		});
	}
};

static inline std::unique_ptr<sinsp_filter_transformer> transformer_factory_create_transformer(
        filter_transformer_type trtype) {
	switch(trtype) {
	case FTR_TOUPPER: {
		return std::make_unique<sinsp_filter_toupper_transformer>();
	}
	case FTR_TOLOWER: {
		return std::make_unique<sinsp_filter_tolower_transformer>();
	}
	case FTR_BASE64: {
		return std::make_unique<sinsp_filter_base64_transformer>();
	}
	case FTR_STORAGE: {
		// for STORAGE, the transformed type is the same as the input type
		// return true;
		return std::make_unique<sinsp_filter_storage_transformer>();
	}
	case FTR_BASENAME: {
		return std::make_unique<sinsp_filter_basename_transformer>();
	}
	default:
		throw_unsupported_err(trtype);
		return nullptr;
	}
}
