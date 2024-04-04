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

#include "sys_call_test.h"

#include "event_capture.h"
#include "event_thread.h"
#include "subprocess.h"

#include <cstdint>
#include <libscap/scap-int.h>
#include <libscap/scap_platform.h>

#include <gtest/gtest.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/quota.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>

#include <algorithm>
#include <cassert>
#include <list>
#include <numeric>


TEST_F(sys_call_test, stat)
{
	event_thread test([]{
		struct stat sb;
		stat("/tmp", &sb);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		std::string evt_name(evt->get_name());
		return evt_name.find("stat") != std::string::npos;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(2, res);
}

TEST_F(sys_call_test, open_close)
{
	event_thread test([]
	{
		int fd = open("/tmp", O_RDONLY);
		close(fd);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return (0 == strcmp(evt->get_name(), "open") ||
				0 == strcmp(evt->get_name(), "openat") ||
		        0 == strcmp(evt->get_name(), "close")) && "<f>/tmp" == evt->get_param_value_str("fd");

	};

	event_capture capture(filter, test);
	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(2, res);
}

TEST_F(sys_call_test, open_close_dropping)
{
	event_thread test([]
	{
		int fd = open("/tmp", O_RDONLY);
		close(fd);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return (0 == strcmp(evt->get_name(), "open") || 0 == strcmp(evt->get_name(), "openat") ||
		        0 == strcmp(evt->get_name(), "close")) && "<f>/tmp" == evt->get_param_value_str("fd");

	};


	event_capture::get_inspector()->start_dropping_mode(1);
	event_capture capture(filter, test);
	capture.start();

	auto res = capture.stop();
	event_capture::get_inspector()->stop_dropping_mode();

	EXPECT_EQ(2, res);
}

TEST_F(sys_call_test, fcntl_getfd)
{
	event_thread test([]{
		fcntl(0, F_GETFL);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "fcntl");
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(2, res);
}

TEST_F(sys_call_test, fcntl_getfd_dropping)
{
	event_thread test([]{
		fcntl(0, F_GETFL);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "fcntl");
	};

	event_capture capture(filter, test);

	event_capture::get_inspector()->start_dropping_mode(1);
	capture.start();

	auto res = capture.stop();
	event_capture::get_inspector()->stop_dropping_mode();

	EXPECT_EQ(0, res);
}

TEST_F(sys_call_test, bind_error)
{
	event_thread test([]{
		bind(0, NULL, 0);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return strcmp(evt->get_name(), "bind") == 0;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(2, res);
}

TEST_F(sys_call_test, bind_error_dropping)
{
	event_thread test([]{
		bind(0, NULL, 0);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return strcmp(evt->get_name(), "bind") == 0;
	};

	event_capture capture(filter, test);

	event_capture::get_inspector()->start_dropping_mode(1);
	capture.start();

	auto res = capture.stop();
	event_capture::get_inspector()->stop_dropping_mode();

	EXPECT_EQ(1, res);
}


TEST_F(sys_call_test, close_badfd_dropping)
{
	event_thread test([]{
		close(-1);
		close(INT_MAX);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		if(strcmp(evt->get_name(), "close") == 0)
		{
			int fd = evt->get_param(0)->as<int64_t>();
			if(evt->get_direction() == SCAP_ED_IN &&
			   (fd == -1 || fd == INT_MAX))
			{
				return true;
			}
			else if(evt->get_direction() == SCAP_ED_OUT && fd == -EBADF)
			{
				return true;
			}
		}
		return false;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(4, res);
}

TEST(inspector, invalid_file_name)
{
	sinsp inspector;
	ASSERT_THROW(inspector.open_savefile("invalid_file_name"), sinsp_exception);
}

TEST_F(sys_call_test, ioctl)
{
	int status;
	event_thread test([&]{
		int fd = open("/dev/ttyS0", O_RDONLY);
		ioctl(fd, TIOCMGET, &status);
		close(fd);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		uint16_t type = evt->get_type();

		if (type == PPME_SYSCALL_IOCTL_3_E)
		{
			std::ostringstream oss;
			oss << std::hex << std::uppercase << TIOCMGET;
			EXPECT_EQ("<f>/dev/ttyS0", evt->get_param_value_str("fd"));
			EXPECT_EQ(oss.str(), evt->get_param_value_str("request"));
			oss.str("");
			oss.clear();
			oss << std::hex << std::uppercase << ((unsigned long)&status);
			EXPECT_EQ(oss.str(), evt->get_param_value_str("argument"));
			return true;
		}
		else if (type == PPME_SYSCALL_IOCTL_3_X)
		{
			std::string res = evt->get_param_value_str("res");
			EXPECT_TRUE(res == "0" || res == "EIO");
			return true;
		}
		return false;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(2, res);
}

TEST_F(sys_call_test, shutdown)
{
	int sock;
	event_thread test([&]{
		if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			FAIL() << "socket() failed";
			return;
		}

		shutdown(sock, SHUT_RD);
		shutdown(sock, SHUT_WR);
		shutdown(sock, SHUT_RDWR);

		close(sock);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		uint16_t type = evt->get_type();

		if (type == PPME_SOCKET_SHUTDOWN_E)
		{
			EXPECT_EQ(std::to_string(sock), evt->get_param_value_str("fd", false));

			switch(event_capture::get_matched_num())
			{
			case 0:
				EXPECT_EQ("0", evt->get_param_value_str("how", false));
				break;
			case 2:
				EXPECT_EQ("1", evt->get_param_value_str("how", false));
				break;
			case 4:
				EXPECT_EQ("2", evt->get_param_value_str("how", false));
				break;
			}
			return true;
		}
		else if (type == PPME_SOCKET_SHUTDOWN_X)
		{
			EXPECT_GT(0, std::stoll(evt->get_param_value_str("res", false)));
			return true;
		}
		return false;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(6, res);
}

TEST_F(sys_call_test, timerfd)
{
	int fd;
	event_thread test([&]{
		int ret;
		unsigned int ns;
		unsigned int sec;
		struct itimerspec itval;
		unsigned int period = 100000;
		unsigned long long missed;

		// Create the timer
		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd == -1)
		{
			FAIL();
		}

		// Make the timer periodic
		sec = period / 1000000;
		ns = (period - (sec * 1000000)) * 1000;
		itval.it_interval.tv_sec = sec;
		itval.it_interval.tv_nsec = ns;
		itval.it_value.tv_sec = sec;
		itval.it_value.tv_nsec = ns;
		ret = timerfd_settime(fd, 0, &itval, NULL);

		// Wait for the next timer event. If we have missed any the
		//number is written to "missed"
		ret = read(fd, &missed, sizeof(missed));
		if (ret == -1)
		{
			FAIL();
		}

		close(fd);
	});


	event_filter_t filter = [&](sinsp_evt* evt)
	{
		uint16_t type = evt->get_type();

		if (type == PPME_SYSCALL_TIMERFD_CREATE_E)
		{
			EXPECT_EQ(0, std::stoll(evt->get_param_value_str("clockid")));
			EXPECT_EQ(0, std::stoll(evt->get_param_value_str("flags")));
			return true;
		}
		else if (type == PPME_SYSCALL_TIMERFD_CREATE_X)
		{
			EXPECT_EQ(fd, std::stoll(evt->get_param_value_str("res", false)));
			return true;
		}
		else if (type == PPME_SYSCALL_READ_E)
		{
			if (event_capture::get_matched_num() == 2)
			{
				EXPECT_EQ("<t>", evt->get_param_value_str("fd"));
				EXPECT_EQ(fd, std::stoll(evt->get_param_value_str("fd", false)));
				return true;
			}
		}
		return false;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(3, res);
}

TEST_F(sys_call_test, DISABLED_timestamp)
{
	static const uint64_t TIMESTAMP_DELTA_NS =
	    1000000;  // We should at least always have 1 ms resolution
	uint64_t timestampv[20];

	event_thread test([&]{
		useconds_t sleep_period = 10;
		struct timeval tv;
		for (int j = 0; j < 20; j++)
		{
			syscall(SYS_gettimeofday, &tv, NULL);
			timestampv[j] = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000;
			usleep(sleep_period);
			sleep_period *= 2;
		}
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		if (evt->get_type() == PPME_GENERIC_X &&
		    evt->get_param_value_str("ID") == "gettimeofday")
		{
			size_t i = event_capture::get_matched_num();
			EXPECT_LE(evt->get_ts(), timestampv[i] + TIMESTAMP_DELTA_NS);
			EXPECT_GE(evt->get_ts(), timestampv[i] - TIMESTAMP_DELTA_NS);
			return true;
		}
		return false;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ((int)(sizeof(timestampv) / sizeof(timestampv[0])), res);
}

TEST_F(sys_call_test, brk)
{
	event_thread test([]{
		struct stat sb;
		stat("/tmp", &sb);
		sbrk(1000);
		sbrk(100000);
	});

	uint32_t before_brk_vmsize;
	uint32_t before_brk_vmrss;
	uint32_t after_brk_vmsize;
	uint32_t after_brk_vmrss;
	bool ignore_this_call = false;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		uint16_t type = evt->get_type();

		if (type == PPME_SYSCALL_BRK_4_E)
		{
			uint64_t addr = evt->get_param_by_name("addr")->as<uint64_t>();
			if (addr == 0)
			{
				ignore_this_call = true;
				return false;
			}
			return true;
		}
		else if (type == PPME_SYSCALL_BRK_4_X)
		{
			if (ignore_this_call)
			{
				ignore_this_call = false;
				return false;
			}

			uint32_t vmsize = evt->get_param_by_name("vm_size")->as<uint32_t>();
			uint32_t vmrss = evt->get_param_by_name("vm_rss")->as<uint32_t>();

			EXPECT_EQ(evt->get_thread_info(false)->m_vmsize_kb, vmsize);
			EXPECT_EQ(evt->get_thread_info(false)->m_vmrss_kb, vmrss);

			if (event_capture::get_matched_num() == 1)
			{
				before_brk_vmsize = vmsize;
				before_brk_vmrss = vmrss;
			}
			else if (event_capture::get_matched_num() == 3)
			{
				after_brk_vmsize = vmsize;
				after_brk_vmrss = vmrss;

				EXPECT_GT(after_brk_vmsize, before_brk_vmsize + 50);
				EXPECT_GE(after_brk_vmrss, before_brk_vmrss);
			}
			return true;
		}
		return false;
	};


	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(4, res);
}

TEST_F(sys_call_test, mmap)
{
	int errno2;
	void* p;
	event_thread test([&]{
		munmap((void*)0x50, 300);
		p = mmap(0,
		         0,
		         PROT_EXEC | PROT_READ | PROT_WRITE,
		         MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE,
		         -1,
		         0);
		EXPECT_EQ((uint64_t)-1, (uint64_t)p);
		errno2 = errno;
		p = mmap(NULL, 1003520, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		EXPECT_NE((uint64_t)0, (uint64_t)p);
		munmap(p, 1003520);
	});

	uint32_t enter_vmsize;
	uint32_t enter_vmrss;
	uint32_t exit_vmsize;
	uint32_t exit_vmrss;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		uint16_t type = evt->get_type();
		uint64_t result;

		if (type == PPME_SYSCALL_MUNMAP_E)
		{
			enter_vmsize = evt->get_thread_info(false)->m_vmsize_kb;
			enter_vmrss = evt->get_thread_info(false)->m_vmrss_kb;

			switch (event_capture::get_matched_num())
			{
			case 0:
				EXPECT_EQ("50", evt->get_param_value_str("addr"));
				EXPECT_EQ("300", evt->get_param_value_str("length"));
				return true;
			case 6:
				uint64_t addr = evt->get_param_by_name("addr")->as<uint64_t>();
#ifdef __LP64__
				EXPECT_EQ((uint64_t)p, addr);
#else
				EXPECT_EQ(((uint32_t)p), addr);
#endif
				EXPECT_EQ("1003520", evt->get_param_value_str("length"));
				return true;
			}
		}
		else if (type == PPME_SYSCALL_MUNMAP_X)
		{
			exit_vmsize = evt->get_param_by_name("vm_size")->as<uint32_t>();
			exit_vmrss = evt->get_param_by_name("vm_rss")->as<uint32_t>();
			EXPECT_EQ(evt->get_thread_info(false)->m_vmsize_kb, exit_vmsize);
			EXPECT_EQ(evt->get_thread_info(false)->m_vmrss_kb, exit_vmrss);

			switch (event_capture::get_matched_num())
			{
			case 1:
				EXPECT_EQ("EINVAL", evt->get_param_value_str("res"));
				EXPECT_EQ("-22", evt->get_param_value_str("res", false));
				return true;
			case 7:
				EXPECT_EQ("0", evt->get_param_value_str("res"));
				EXPECT_GT(enter_vmsize, exit_vmsize + 500);
				EXPECT_GE(enter_vmrss, enter_vmrss);
				return true;
			}
		}
		else if (type == PPME_SYSCALL_MMAP_E || type == PPME_SYSCALL_MMAP2_E)
		{
			enter_vmsize = evt->get_thread_info(false)->m_vmsize_kb;
			enter_vmrss = evt->get_thread_info(false)->m_vmrss_kb;

			switch (event_capture::get_matched_num())
			{
			case 2:
				EXPECT_EQ("0", evt->get_param_value_str("addr"));
				EXPECT_EQ("0", evt->get_param_value_str("length"));
				EXPECT_EQ("PROT_READ|PROT_WRITE|PROT_EXEC", evt->get_param_value_str("prot"));
				EXPECT_EQ("MAP_SHARED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_DENYWRITE",
				          evt->get_param_value_str("flags"));
#ifdef __LP64__
				// It looks that starting from kernel 4.9, fd is -1 also on 64bit
				EXPECT_TRUE(evt->get_param_value_str("fd", false) == "4294967295" ||
				            evt->get_param_value_str("fd", false) == "-1");
#else
				EXPECT_EQ("-1", evt->get_param_value_str("fd", false));
#endif
				if (type == PPME_SYSCALL_MMAP_E)
				{
					EXPECT_EQ("0", evt->get_param_value_str("offset"));
				}
				else
				{
					EXPECT_EQ("0", evt->get_param_value_str("pgoffset"));
				}
				return true;
			case 4:
				EXPECT_EQ("0", evt->get_param_value_str("addr"));
				EXPECT_EQ("1003520", evt->get_param_value_str("length"));
				EXPECT_EQ("PROT_READ|PROT_WRITE", evt->get_param_value_str("prot"));
				EXPECT_EQ("MAP_PRIVATE|MAP_ANONYMOUS", evt->get_param_value_str("flags"));
#ifdef __LP64__
				EXPECT_TRUE(evt->get_param_value_str("fd", false) == "4294967295" ||
				            evt->get_param_value_str("fd", false) == "-1");
#else
				EXPECT_EQ("-1", evt->get_param_value_str("fd", false));
#endif
				if (type == PPME_SYSCALL_MMAP_E)
				{
					EXPECT_EQ("0", evt->get_param_value_str("offset"));
				}
				else
				{
					EXPECT_EQ("0", evt->get_param_value_str("pgoffset"));
				}
				return true;
			}
		}
		else if (type == PPME_SYSCALL_MMAP_X || type == PPME_SYSCALL_MMAP2_X)
		{
			exit_vmsize = evt->get_param_by_name("vm_size")->as<uint32_t>();
			exit_vmrss = evt->get_param_by_name("vm_rss")->as<uint32_t>();
			EXPECT_EQ(evt->get_thread_info(false)->m_vmsize_kb, exit_vmsize);
			EXPECT_EQ(evt->get_thread_info(false)->m_vmrss_kb, exit_vmrss);

			switch (event_capture::get_matched_num())
			{
			case 3:
				result = evt->get_param_by_name("res")->as<uint64_t>();
				EXPECT_EQ(-errno2, (int64_t)result);
				return true;
			case 5:
				result = evt->get_param_by_name("res")->as<uint64_t>();
				EXPECT_EQ((uint64_t)p, result);
				EXPECT_GT(exit_vmsize, enter_vmsize + 500);
				EXPECT_GE(exit_vmrss, enter_vmrss);
				return true;
			}
		}
		return false;
	};
	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(8, res);
}

TEST_F(sys_call_test, quotactl_ko)
{
	event_thread test([]{
		quotactl(QCMD(Q_QUOTAON, USRQUOTA),
		         "/dev/xxx",
		         2,
		         (caddr_t) "/quota.user");  // 2 => QFMT_VFS_V0
		quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/xxx", 0, NULL);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		uint16_t type = evt->get_type();
		if (type == PPME_SYSCALL_QUOTACTL_E)
		{
			switch (event_capture::get_matched_num())
			{
			case 0:
				EXPECT_EQ("Q_QUOTAON", evt->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", evt->get_param_value_str("type"));
				EXPECT_EQ("QFMT_VFS_V0", evt->get_param_value_str("quota_fmt"));
				return true;
			case 2:
				EXPECT_EQ("Q_QUOTAOFF", evt->get_param_value_str("cmd"));
				EXPECT_EQ("GRPQUOTA", evt->get_param_value_str("type"));
				return true;
			}
		}
		else if (type == PPME_SYSCALL_QUOTACTL_X)
		{
			switch (event_capture::get_matched_num())
			{
			case 1:
				EXPECT_EQ("-2", evt->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", evt->get_param_value_str("special"));
				EXPECT_EQ("/quota.user", evt->get_param_value_str("quotafilepath"));
				return true;
			case 3:
				EXPECT_EQ("-2", evt->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", evt->get_param_value_str("special"));
				return true;
			}
		}
		return false;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(4, res);
}

TEST_F(sys_call_test, quotactl_ok)
{
	struct dqblk mydqblk;
	struct dqinfo mydqinfo;
	event_thread test([&]{
		quotactl(QCMD(Q_QUOTAON, USRQUOTA),
		         "/dev/loop0",
		         2,
		         (caddr_t) "/tmp/testquotamnt/aquota.user");  // 2 => QFMT_VFS_V0
		quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/dev/loop0", 0, (caddr_t)&mydqblk);  // 0 => root user
		quotactl(QCMD(Q_GETINFO, USRQUOTA), "/dev/loop0", 0, (caddr_t)&mydqinfo);
		quotactl(QCMD(Q_QUOTAOFF, USRQUOTA), "/dev/loop0", 0, NULL);
	});

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		uint16_t type = evt->get_type();
		if (type == PPME_SYSCALL_QUOTACTL_E)
		{
			switch (event_capture::get_matched_num())
			{
			case 0:
				EXPECT_EQ("Q_QUOTAON", evt->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", evt->get_param_value_str("type"));
				EXPECT_EQ("QFMT_VFS_V0", evt->get_param_value_str("quota_fmt"));
				break;
			case 2:
				EXPECT_EQ("Q_GETQUOTA", evt->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", evt->get_param_value_str("type"));
				EXPECT_EQ("0", evt->get_param_value_str("id"));
				break;
			case 4:
				EXPECT_EQ("Q_GETINFO", evt->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", evt->get_param_value_str("type"));
				break;
			case 6:
				EXPECT_EQ("Q_QUOTAOFF", evt->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", evt->get_param_value_str("type"));
				break;
			}
		}
		else if (type == PPME_SYSCALL_QUOTACTL_X)
		{
			switch (event_capture::get_matched_num())
			{
			case 1:
				EXPECT_EQ("0", evt->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", evt->get_param_value_str("special"));
				EXPECT_EQ("/tmp/testquotamnt/aquota.user", evt->get_param_value_str("quotafilepath"));
				return true;
			case 3:
				EXPECT_EQ("0", evt->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", evt->get_param_value_str("special"));
				EXPECT_EQ(mydqblk.dqb_bhardlimit,
				          *reinterpret_cast<const uint64_t*>(
				              evt->get_param_by_name("dqb_bhardlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_bsoftlimit,
				          *reinterpret_cast<const uint64_t*>(
				              evt->get_param_by_name("dqb_bsoftlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_curspace,
				          *reinterpret_cast<const uint64_t*>(
				              evt->get_param_by_name("dqb_curspace")->m_val));
				EXPECT_EQ(mydqblk.dqb_ihardlimit,
				          *reinterpret_cast<const uint64_t*>(
				              evt->get_param_by_name("dqb_ihardlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_isoftlimit,
				          *reinterpret_cast<const uint64_t*>(
				              evt->get_param_by_name("dqb_isoftlimit")->m_val));
				EXPECT_EQ(
				    mydqblk.dqb_btime,
				    *reinterpret_cast<const uint64_t*>(evt->get_param_by_name("dqb_btime")->m_val));
				EXPECT_EQ(
				    mydqblk.dqb_itime,
				    *reinterpret_cast<const uint64_t*>(evt->get_param_by_name("dqb_itime")->m_val));
				return true;
			case 5:
				EXPECT_EQ("0", evt->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", evt->get_param_value_str("special"));
				EXPECT_EQ(
				    mydqinfo.dqi_bgrace,
				    *reinterpret_cast<const uint64_t*>(evt->get_param_by_name("dqi_bgrace")->m_val));
				EXPECT_EQ(
				    mydqinfo.dqi_igrace,
				    *reinterpret_cast<const uint64_t*>(evt->get_param_by_name("dqi_igrace")->m_val));
				return true;
			case 7:
				EXPECT_EQ("0", evt->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", evt->get_param_value_str("special"));
				return true;
			}
		}
		return false;
	};

	// Clean environment
	auto ret = system("umount /tmp/testquotamnt");
	ret = system("rm -rf /tmp/testquotactl /tmp/testquotamnt");
	// Setup a tmpdisk to test quotas
	char command[] =
	    "dd if=/dev/zero of=/tmp/testquotactl bs=1M count=200 &&\n"
	    "echo y | mkfs.ext4 -q /tmp/testquotactl &&\n"
	    "mkdir -p /tmp/testquotamnt &&\n"
	    "mount -o usrquota,grpquota,loop=/dev/loop0 /tmp/testquotactl /tmp/testquotamnt &&\n"
	    "quotacheck -cug /tmp/testquotamnt";
	ret = system(command);
	if (ret != 0)
	{
		GTEST_SKIP() << "quota utilities are missing.";
		return;
	}

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(8, res);
}

TEST_F(sys_call_test, getsetuid_and_gid)
{
	event_filter_t filter = [&](sinsp_evt* e)
	{
		uint16_t type = e->get_type();
		switch (type)
		{
		case PPME_SYSCALL_SETUID_E:
			EXPECT_EQ("0", e->get_param_value_str("uid", false));
			EXPECT_EQ("root", e->get_param_value_str("uid"));
			return true;
			break;
		case PPME_SYSCALL_SETUID_X:
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			return true;
			break;
		case PPME_SYSCALL_SETGID_E:
			EXPECT_EQ("6566", e->get_param_value_str("gid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("gid"));
			return true;
			break;
		case PPME_SYSCALL_SETGID_X:
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			return true;
			break;
		case PPME_SYSCALL_GETUID_X:
			EXPECT_EQ("0", e->get_param_value_str("uid", false));
			EXPECT_EQ("root", e->get_param_value_str("uid"));
			return true;
			break;
		case PPME_SYSCALL_GETEUID_X:
			EXPECT_EQ("0", e->get_param_value_str("euid", false));
			EXPECT_EQ("root", e->get_param_value_str("euid"));
			return true;
			break;
		case PPME_SYSCALL_GETGID_X:
			EXPECT_EQ("6566", e->get_param_value_str("gid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("gid"));
			return true;
			break;
		case PPME_SYSCALL_GETEGID_X:
			EXPECT_EQ("6566", e->get_param_value_str("egid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("egid"));
			return true;
			break;
		case PPME_SYSCALL_GETUID_E:
		case PPME_SYSCALL_GETEUID_E:
		case PPME_SYSCALL_GETGID_E:
		case PPME_SYSCALL_GETEGID_E:
			return true;
			break;
		default:
			return false;
		}
	};

	uint32_t orig_uid  = getuid();
	uint32_t orig_euid = geteuid();
	uint32_t orig_gid  = getgid();
	uint32_t orig_egid = getegid();

	event_thread test([]{
		auto res = setuid(0);
		EXPECT_EQ(0, res);
		res = setgid(6566);
		EXPECT_EQ(0, res);
		getuid();
		geteuid();
		getgid();
		getegid();
	});


	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	int result = 0;
	result += setuid(orig_uid);
	result += seteuid(orig_euid);
	result += setgid(orig_gid);
	result += setegid(orig_egid);

	if(result != 0)
	{
		FAIL() << "Cannot restore initial id state.";
	}

	EXPECT_EQ(12, res);
}

#ifdef __x86_64__

TEST_F(sys_call_test32, execve_ia32_emulation)
{
	event_thread test([]{
		auto ret = system(LIBSINSP_TEST_RESOURCES_PATH "execve32 "
						  LIBSINSP_TEST_RESOURCES_PATH "execve "
						  LIBSINSP_TEST_RESOURCES_PATH "execve32");
		EXPECT_EQ(0, ret);
	});

	sinsp_filter_compiler compiler(event_capture::get_inspector(),
						"evt.type=execve and proc.apid=" + std::to_string(::gettid()));
	std::unique_ptr<sinsp_filter> is_subprocess_execve = compiler.compile();

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		if(is_subprocess_execve->run(evt))
		{
			uint16_t type = evt->get_type();
			auto tinfo = evt->get_thread_info(true);
			if (type == PPME_SYSCALL_EXECVE_19_E || type == PPME_SYSCALL_EXECVE_18_E ||
				type == PPME_SYSCALL_EXECVE_17_E)
			{
				switch (event_capture::get_matched_num())
				{
					case 0:
						EXPECT_EQ(tinfo->m_comm, "libsinsp_e2e_te");
						break;
					case 2:
						EXPECT_EQ(tinfo->m_comm, "sh");
						break;
					case 4:
						EXPECT_EQ(tinfo->m_comm, "execve32");
						break;
					case 6:
						EXPECT_EQ(tinfo->m_comm, "execve");
						break;
					default:
						return false;
				}
				return true;
			}
			else if (type == PPME_SYSCALL_EXECVE_19_X || type == PPME_SYSCALL_EXECVE_18_X ||
					 type == PPME_SYSCALL_EXECVE_17_X)
			{
				EXPECT_EQ("0", evt->get_param_value_str("res", false));
				auto comm = evt->get_param_value_str("comm", false);
				switch (event_capture::get_matched_num())
				{
					case 1:
						EXPECT_EQ(comm, "sh");
						break;
					case 3:
						EXPECT_EQ(comm, "execve32");
						break;
					case 5:
						EXPECT_EQ(comm, "execve");
						break;
					case 7:
						EXPECT_EQ(comm, "execve32");
						break;
					default:
						return false;
				}
			}
			return true;
		}
		return false;
	};

	event_capture capture(filter, test);

	capture.disable_tid_filter(true);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(8, res);
}

TEST_F(sys_call_test32, quotactl_ko)
{
	event_thread test([]{
		subprocess handle(LIBSINSP_TEST_PATH "/test_helper_32", {"quotactl_ko"});
		handle.wait();
	});

	event_filter_t filter = [&](sinsp_evt* e)
	{
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_QUOTACTL_E)
		{
			switch (event_capture::get_matched_num())
			{
			case 0:
				EXPECT_EQ("Q_QUOTAON", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				EXPECT_EQ("QFMT_VFS_V0", e->get_param_value_str("quota_fmt"));
				break;
			case 2:
				EXPECT_EQ("Q_QUOTAOFF", e->get_param_value_str("cmd"));
				EXPECT_EQ("GRPQUOTA", e->get_param_value_str("type"));
				break;
			default:
				return false;
			}
			return true;
		}
		else if (type == PPME_SYSCALL_QUOTACTL_X)
		{
			switch (event_capture::get_matched_num())
			{
			case 1:
				EXPECT_EQ("-2", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", e->get_param_value_str("special"));
				EXPECT_EQ("/quota.user", e->get_param_value_str("quotafilepath"));
				break;
			case 3:
				EXPECT_EQ("-2", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", e->get_param_value_str("special"));
				break;
			default:
				return false;
			}
			return true;
		}
		return false;
	};

	event_capture capture(filter, test);

	capture.disable_tid_filter(true);

	capture.use_subprocess(true);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(4, res);
}

#endif

TEST_F(sys_call_test, setns_test)
{
	event_thread test([]{
		int fd = open("/proc/self/ns/net", O_RDONLY);
		ASSERT_NE(0, fd);
		ASSERT_EQ(0, setns(fd, CLONE_NEWNET));
		ASSERT_EQ(0, close(fd));
	});

	event_filter_t filter = [&](sinsp_evt* e)
	{
		uint16_t type = e->get_type();
		switch (type)
		{
		case PPME_SYSCALL_SETNS_E:
			EXPECT_EQ("<f>/proc/self/ns/net", e->get_param_value_str("fd"));
			break;
		case PPME_SYSCALL_SETNS_X:
			EXPECT_EQ("0", e->get_param_value_str("res"));
			break;
		default:
			return false;
		}
		return true;
	};

	event_capture capture(filter, test);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(2, res);
}

TEST_F(sys_call_test, unshare_)
{
	event_thread test([]{
		auto child = fork();
		if (child == 0)
		{
			unshare(CLONE_NEWUTS);
			// _exit prevents asan from complaining for a false positive memory leak.
			_exit(0);
		}
		waitpid(child, NULL, 0);
	});

	event_filter_t filter = [&](sinsp_evt* e)
	{
		uint16_t type = e->get_type();
		switch (type)
		{
		case PPME_SYSCALL_UNSHARE_E:
			EXPECT_EQ("CLONE_NEWUTS", e->get_param_value_str("flags"));
			break;
		case PPME_SYSCALL_UNSHARE_X:
			EXPECT_EQ("0", e->get_param_value_str("res"));
			break;
		default:
			return false;
		}
		return true;
	};

	event_capture capture(filter, test);

	capture.disable_tid_filter(true);

	capture.use_subprocess(true);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(2, res);
}

TEST_F(sys_call_test, sendmsg_recvmsg_SCM_RIGHTS)
{
	event_thread test([]{
		int server_sd, worker_sd, pair_sd[2];
		int rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_sd);
		ASSERT_GE(rc, 0);
		server_sd = pair_sd[0];
		worker_sd = pair_sd[1];

		auto child = fork();
		if (child == 0)
		{
			struct msghdr child_msg = {};
			struct cmsghdr *cmsghdr;
			struct iovec iov[1];
			char buf[CMSG_SPACE(sizeof(int))], c;

			iov[0].iov_base = &c;
			iov[0].iov_len = sizeof(c);
			memset(buf, 0x0d, sizeof(buf));
			cmsghdr = (struct cmsghdr *)buf;
			cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
			cmsghdr->cmsg_level = SOL_SOCKET;
			cmsghdr->cmsg_type = SCM_RIGHTS;
			child_msg.msg_iov = iov;
			child_msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
			child_msg.msg_control = cmsghdr;
			child_msg.msg_controllen = CMSG_LEN(sizeof(int));
			rc = recvmsg(worker_sd, &child_msg, 0);
			ASSERT_GE(rc, 0);
			// _exit prevents asan from complaining for a false positive memory leak.
			_exit(0);
		}
		else
		{
			struct msghdr parent_msg = {};
			struct cmsghdr *cmsghdr;
			struct iovec iov[1];
			int *p;
			char buf[CMSG_SPACE(sizeof(int))], c;

			FILE *f = tmpfile();
			ASSERT_NE(nullptr, f);
			int fd = fileno(f);

			c = '*';
			iov[0].iov_base = &c;
			iov[0].iov_len = sizeof(c);
			memset(buf, 0x0b, sizeof(buf));
			cmsghdr = (struct cmsghdr *)buf;
			cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
			cmsghdr->cmsg_level = SOL_SOCKET;
			cmsghdr->cmsg_type = SCM_RIGHTS;
			parent_msg.msg_iov = iov;
			parent_msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
			parent_msg.msg_control = cmsghdr;
			parent_msg.msg_controllen = CMSG_LEN(sizeof(int));
			p = (int *)CMSG_DATA(cmsghdr);
			*p = fd;

			rc = sendmsg(server_sd, &parent_msg, 0);
			ASSERT_GE(rc, 0);
			waitpid(child, NULL, 0);
			fclose(f);
		}
	});

	event_filter_t filter = [&](sinsp_evt* e)
	{
		if(e->get_type() == PPME_SOCKET_RECVMSG_X && e->get_num_params() >= 5)
		{
			auto parinfo = e->get_param(4);
			if(parinfo->m_len > sizeof(cmsghdr))
			{
				cmsghdr cmsg = {};
				memcpy(&cmsg, parinfo->m_val, sizeof(cmsghdr));
				if(cmsg.cmsg_type == SCM_RIGHTS)
				{
					return true;
				}
			}
		}
		return false;
	};
	event_capture capture(filter, test);

	capture.disable_tid_filter(true);

	capture.start();

	auto res = capture.stop();

	EXPECT_EQ(1, res);
}
