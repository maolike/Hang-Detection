#include <windows.h>
#include "detours.h"
#include <DbgHelp.h>
#include <process.h>
#include <chrono>
#include "hangdetect.h"

#include "stackwalkhelper.h"
#include "threadhangmonitor.h"

typedef LRESULT(WINAPI* func_DispatchMessage)(_In_ CONST MSG*);
func_DispatchMessage gOriginDispatchMessageW = NULL;
DWORD gMainThreadId = 0;
HANDLE gMainThread = NULL;
unsigned int gMsg[100];
unsigned int gMsgCount = 0;

bool matchMsg(unsigned int msg)
{
	for (unsigned int i = 0; i < gMsgCount; ++i)
	{
		if (gMsg[i] == msg)
			return false;
	}
	return true;
}

LRESULT WINAPI gMyDispatchMessageW(_In_ CONST MSG* lpMsg)
{
	if (matchMsg(lpMsg->message) && ::GetCurrentThreadId() == gMainThreadId)
	{
		ThreadHangMonitor::Instance()->startMonitor(lpMsg->message);
		BOOL ret = gOriginDispatchMessageW(lpMsg);
		ThreadHangMonitor::Instance()->stopMonitor();
		return ret;
	}
	return gOriginDispatchMessageW(lpMsg);
}

ThreadHangMonitor* ThreadHangMonitor::Instance()
{
	static ThreadHangMonitor instance;
	return &instance;
}

ThreadHangMonitor::ThreadHangMonitor()
{
}

ThreadHangMonitor::~ThreadHangMonitor()
{
	release();
}

void ThreadHangMonitor::init()
{
	if (!_init)
	{
		_monitorThread = NULL;
		_hwnd = NULL;
		_entryTimes = 0;
		_init = false;
		_exitNow = false;

		HMODULE h = LoadLibrary(L"user32.dll");
		if (!h)
			return;
		gOriginDispatchMessageW = (func_DispatchMessage)GetProcAddress(h, "DispatchMessageW");

		gMainThreadId = ::GetCurrentThreadId();
		HANDLE mainThread = ::GetCurrentThread();
		if (::DuplicateHandle(::GetCurrentProcess(), mainThread, ::GetCurrentProcess(), &gMainThread, NULL, FALSE,
			DUPLICATE_SAME_ACCESS)
			!= TRUE)
		{
			return;
		}
		hookDispatchMessage();
		_monitorThread = (HANDLE)_beginthreadex(NULL, 0, &ThreadHangMonitor::MonitorThreadRoutine, (void*)this, 0, NULL);
		if (_monitorThread == NULL)
		{
			unHookDispatchMessage();
			::CloseHandle(gMainThread);
			return;
		}
		_init = true;
	}
}

void ThreadHangMonitor::release()
{
	if (_init)
	{
		_init = false;
		_exitNow = true;
		if (_monitorThread)
		{
			SetTimer(_hwnd, 2, 100, NULL);
			PostMessageA(_hwnd, WM_QUIT, 0, 0);
			WaitForSingleObject(_monitorThread, INFINITE);
			::CloseHandle(_monitorThread);
			_hwnd = NULL;
			_monitorThread = NULL;
		}
		unHookDispatchMessage();
		::CloseHandle(gMainThread);
	}
}

void ThreadHangMonitor::monitorMsg(const std::vector<unsigned int>& msg)
{
	for (size_t i = 0; i < msg.size() && i < ARRAYSIZE(gMsg); ++i)
	{
		gMsg[i] = msg[i];
	}
	gMsgCount = msg.size();
}

void ThreadHangMonitor::hookDispatchMessage()
{
	DetourTransactionBegin();
	DetourUpdateThread(::GetCurrentThread());
	DetourAttach(&(PVOID&)gOriginDispatchMessageW, gMyDispatchMessageW);
	DetourTransactionCommit();
}

void ThreadHangMonitor::unHookDispatchMessage()
{
	DetourTransactionBegin();
	DetourUpdateThread(::GetCurrentThread());
	DetourDetach(&(PVOID&)gOriginDispatchMessageW, gMyDispatchMessageW);
	DetourTransactionCommit();
}

void ThreadHangMonitor::startMonitor(unsigned int message)
{
	_entryTimes++;
	if (_entryTimes == 1)
	{
		_message = message;
		_entryTimePoint = std::chrono::steady_clock::now();
	}
}

void ThreadHangMonitor::stopMonitor()
{
	if (_entryTimes > 0)
	{
		_entryTimes--;
		if (_entryTimes == 0)
		{
			_message = 0;
			_entryTimePoint = std::chrono::steady_clock::time_point();
			_lastHangEntryTimePoint = std::chrono::steady_clock::time_point();
		}
	}
}

unsigned int __stdcall ThreadHangMonitor::MonitorThreadRoutine(LPVOID param)
{
	ThreadHangMonitor* monitor = (ThreadHangMonitor*)param;
	monitor->run();
	return 0;
}

void ThreadHangMonitor::run()
{
	_hwnd = ::CreateWindowW(L"STATIC", L"ThreadHangMonitor", WS_POPUP, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
	::SetWindowLongPtr(_hwnd, GWLP_USERDATA, (LONG_PTR)this);
	::SetWindowLongPtr(_hwnd, GWLP_WNDPROC, (LONG_PTR)ThreadHangMonitor::WindowRoutine);
	if (_hwnd != NULL)
	{
		MSG msg;
		SetTimer(_hwnd, 1, timerTime(), NULL);
		while (GetMessageA(&msg, _hwnd, 0, 0) && !_exitNow)
		{
			TranslateMessage(&msg);
			DispatchMessageA(&msg);
		}
	}
	DestroyWindow(_hwnd);
}

LRESULT CALLBACK ThreadHangMonitor::WindowRoutine(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	ThreadHangMonitor* pThis = (ThreadHangMonitor*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
	return pThis->process(hwnd, uMsg, wParam, lParam);
}

LRESULT ThreadHangMonitor::process(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_TIMER:
	{
		unsigned int message = _message;
		auto entryPointTime = _entryTimePoint;
		if (entryPointTime != std::chrono::steady_clock::time_point() && message != 0 && wParam == 1)
		{
			auto now = std::chrono::steady_clock::now();
			long long duration = std::chrono::duration_cast<std::chrono::milliseconds> (now - entryPointTime).count();
			if (duration > HANGDETECT::getHangTime() && _lastHangEntryTimePoint != entryPointTime)
			{
				_lastHangEntryTimePoint = entryPointTime;
				if (IsDebuggerPresent())
				{	//don't record if debug
					PostMessageA(_hwnd, WM_QUIT, 0, 0);
					return 0;
				}

				callstack::StackWalkResult result;
				if (StackWalkHelper::Instance()->stackWalkOtherThread(gMainThread, &result))
				{
					auto time = std::chrono::system_clock::now();
					std::time_t currentTime = std::chrono::system_clock::to_time_t(time);
					std::tm timeinfo;
					localtime_s(&timeinfo, &currentTime);
					char buffer[80];
					std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
					result.timePoint = buffer;
					result.hangTime = duration;
					result.message = message;
					std::string str = callstack::Utils::toJsonString(result);
					TCHAR lpTempPathBuffer[MAX_PATH];
					DWORD dwRetVal = 0;
					dwRetVal = ::GetTempPath(MAX_PATH, lpTempPathBuffer);
					if (dwRetVal > MAX_PATH || (dwRetVal == 0))
						break;

					std::wstring tempDir = lpTempPathBuffer;
					std::wstring file = tempDir + L"hangs.log";
					FILE* f = NULL;
					_wfopen_s(&f, file.c_str(), L"a+");
					if (f == NULL)
					{
						break;
					}
					str.append(1, '\n');
					fwrite(str.c_str(), str.size(), 1, f);
					fclose(f);
				}
				SetTimer(_hwnd, 1, timerTime(), NULL);
				break;
			}
			else
			{
				//the window specified by hWnd already has a timer with the value nIDEvent,
				//then the existing timer is replaced by the new timer.
				//When SetTimer replaces a timer, the timer is reset.
				//Therefore, a message will be sent after the current time - out value elapses,
				//but the previously set time - out value is ignored.
				SetTimer(_hwnd, 1, timerTime(), NULL);
			}
		}
		else
		{
			SetTimer(_hwnd, 1, timerTime(), NULL);
		}
	}
	default:
		break;
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int ThreadHangMonitor::timerTime()
{
	int time = HANGDETECT::getHangTime() / 4;
	return time < 100 ? 100 : (time > 1000 ? 1000 : time);
}

