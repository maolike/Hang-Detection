#pragma once

#include <windows.h>
#include <vector>
#include <chrono>

class ThreadHangMonitor
{
public:
    static ThreadHangMonitor* Instance();
    ~ThreadHangMonitor();
    void monitorMsg(const std::vector<unsigned int>& msg);
    void init();
    void release();
    void startMonitor(unsigned int message);
    void stopMonitor();
private:
    ThreadHangMonitor();
    void hookDispatchMessage();
    void unHookDispatchMessage();
    static unsigned int __stdcall MonitorThreadRoutine(LPVOID param);
    void run();
    static LRESULT CALLBACK WindowRoutine(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam );
    LRESULT process(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam );
    int timerTime();

private:
    HANDLE _monitorThread;
    HWND _hwnd;
    int _entryTimes;
    int _message;
    bool _init;
    std::chrono::steady_clock::time_point _entryTimePoint;
    std::chrono::steady_clock::time_point _lastHangEntryTimePoint;
	int _exitNow;
};
