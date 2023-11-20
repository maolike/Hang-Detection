#pragma once
#include <map>
#include <set>
#include <string>
#include <vector>
#include <windows.h>
#include <DbgHelp.h>
#include <chrono>
#include "callstackdef.h"
extern HWND g_wnd;
class StackWalkHelper
{
public:
    static StackWalkHelper* Instance();
    ~StackWalkHelper();
    bool stackWalkOtherThread(HANDLE hThread, callstack::StackWalkResult* output);

private:
    StackWalkHelper();
    int init();
    bool isSystemDll(const std::string& imageName);
    std::string readPdbSig70(const std::string& imageName, ULONGLONG base, ULONGLONG end);
    std::vector<DWORD64> stackwalk64(HANDLE hThread);
    void fillContent(const std::vector<DWORD64>& offset, callstack::StackWalkResult* output);
    static unsigned int __stdcall checkThreadRoutine(LPVOID param);
    void checkThreadRun();
    bool isPdbSig70Unknow(callstack::StackWalkResult* output);

private:
    int _init;
    HMODULE _hDbgHelp;
    std::map<std::string, bool> _systemDll;


    typedef BOOL(__stdcall* func_SymCleanup)(IN HANDLE hProcess);
    func_SymCleanup _SymCleanup;

    typedef PVOID(__stdcall* func_SymFunctionTableAccess64)(HANDLE hProcess, DWORD64 AddrBase);
    func_SymFunctionTableAccess64 _SymFunctionTableAccess64;

    typedef DWORD64(__stdcall* func_SymGetModuleBase64)(IN HANDLE hProcess, IN DWORD64 dwAddr);
    func_SymGetModuleBase64 _SymGetModuleBase64;

    typedef BOOL(__stdcall* func_SymGetModuleInfo64)(IN HANDLE hProcess, IN DWORD64 dwAddr, OUT IMAGEHLP_MODULE64* ModuleInfo);
    func_SymGetModuleInfo64 _SymGetModuleInfo64;

    typedef BOOL(__stdcall* func_SymInitialize)(IN HANDLE hProcess, IN LPCSTR UserSearchPath, IN BOOL fInvadeProcess);
    func_SymInitialize _SymInitialize;

    typedef DWORD(__stdcall* func_SymSetOptions)(IN DWORD SymOptions);
    func_SymSetOptions _SymSetOptions;

    typedef BOOL(__stdcall* func_StackWalk64)(DWORD MachineType, HANDLE hProcess, HANDLE hThread, LPSTACKFRAME64 StackFrame,
                                 PVOID ContextRecord, PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
                                 PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                                 PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
                                 PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
    func_StackWalk64 _StackWalk64;
    HANDLE _checkThread;
    int _exitNow;
    HANDLE _wakeupEvent;
	int _mainThreadSuspend;
	std::chrono::steady_clock::time_point _mainThreadSuspendTimePoint;
	bool _stackWalkTimeout;
	int _mainThread;
};
