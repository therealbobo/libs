#pragma once

#include <unistd.h>
#include <sys/ioctl.h>

#include <future>
#include <thread>

class event_thread
{
public:
	event_thread(std::function<void()> func):
        m_abort(false),
		m_tid(-1)
    {
        std::promise<void> tid_starter;
        thread = std::thread([this, func, &tid_starter]() mutable {
                m_tid = gettid();
                tid_starter.set_value();
                thread_starter.get_future().wait();
                if(!m_abort)
                {
                    func();
                    // signal that the capture can end.
                    syscall(1337);
                }
            });

        tid_starter.get_future().wait();
    }

    ~event_thread()
    {
        if(thread.joinable())
        {
            start();
            thread.join();
        }
    }

    void start()
    {
        thread_starter.set_value();
    }

    void join()
    {
        if(thread.joinable())
        {
            thread.join();
        }
    }

    pid_t get_tid()
    {
        return m_tid;
    }


private:
    std::promise<void> thread_starter;
    std::atomic<bool> m_abort;
    std::thread thread;
    pid_t m_tid;
};
