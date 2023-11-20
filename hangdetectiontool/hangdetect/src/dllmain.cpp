// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <windows.h>
#include <string>
#include "hangdetect.h"
#include "detours.h"

BOOL ProcessAttach(HMODULE hDll)
{
	wchar_t time[255]={0};
	GetEnvironmentVariable(L"quality-block-time",time,sizeof(time));
	std::wstring str = time;
	if (str.empty())
		return TRUE;
	int t = std::stoi(str);
	HANGDETECT::setHangTime(t);
	HANGDETECT::start();
	return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
	HANGDETECT::stop();
	return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	(void)hModule;
	(void)lpReserved;
	BOOL ret;

	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		DetourRestoreAfterWith();
		return ProcessAttach(hModule);
	case DLL_PROCESS_DETACH:
		ret = ProcessDetach(hModule);
		return ret;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

