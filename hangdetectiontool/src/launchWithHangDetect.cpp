//////////////////////////////////////////////////////////////////////////////
//
//  Test DetourCreateProcessWithDll function (withdll.cpp).
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <string>
#include "detours.h"
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable:6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)

#ifdef _DEBUG
#define  DLLNAME "../bin/debug/hangdetect.dll"
#else
#define DLLNAME "hangdetect.dll"
#endif // DEBUG

//////////////////////////////////////////////////////////////////////////////
//
void PrintUsage(void)
{
	printf("Usage:\n"
		"    launchWithBlockDetectDll.exe [options] [command line]\n"
		"\n"
		"Description:\n"
		"When the main thread block for more than the set time, \n"
		"it will capture the call stack and record it in the local %%temp%%hangs.log file.\n"
		"\n"
		"Options:\n"
		"    /t            : block time (default 2000ms)\n"
		"    /v            : Verbose, display memory at start.\n"
		"    /?            : This help screen.\n");
}

//////////////////////////////////////////////////////////////////////////////
//
//  This code verifies that the named DLL has been configured correctly
//  to be imported into the target process.  DLLs must export a function with
//  ordinal #1 so that the import table touch-up magic works.
//
struct ExportContext
{
	BOOL    fHasOrdinal1;
	ULONG   nExports;
};

static BOOL CALLBACK ExportCallback(_In_opt_ PVOID pContext,
	_In_ ULONG nOrdinal,
	_In_opt_ LPCSTR pszSymbol,
	_In_opt_ PVOID pbTarget)
{
	(void)pContext;
	(void)pbTarget;
	(void)pszSymbol;

	ExportContext* pec = (ExportContext*)pContext;

	if (nOrdinal == 1) {
		pec->fHasOrdinal1 = TRUE;
	}
	pec->nExports++;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//

//////////////////////////////////////////////////////////////////////////////
//

void TypeToString(DWORD Type, char* pszBuffer, size_t cBuffer)
{
	if (Type == MEM_IMAGE) {
		StringCchPrintfA(pszBuffer, cBuffer, "img");
	}
	else if (Type == MEM_MAPPED) {
		StringCchPrintfA(pszBuffer, cBuffer, "map");
	}
	else if (Type == MEM_PRIVATE) {
		StringCchPrintfA(pszBuffer, cBuffer, "pri");
	}
	else {
		StringCchPrintfA(pszBuffer, cBuffer, "%x", Type);
	}
}

void StateToString(DWORD State, char* pszBuffer, size_t cBuffer)
{
	if (State == MEM_COMMIT) {
		StringCchPrintfA(pszBuffer, cBuffer, "com");
	}
	else if (State == MEM_FREE) {
		StringCchPrintfA(pszBuffer, cBuffer, "fre");
	}
	else if (State == MEM_RESERVE) {
		StringCchPrintfA(pszBuffer, cBuffer, "res");
	}
	else {
		StringCchPrintfA(pszBuffer, cBuffer, "%x", State);
	}
}

void ProtectToString(DWORD Protect, char* pszBuffer, size_t cBuffer)
{
	if (Protect == 0) {
		StringCchPrintfA(pszBuffer, cBuffer, "");
	}
	else if (Protect == PAGE_EXECUTE) {
		StringCchPrintfA(pszBuffer, cBuffer, "--x");
	}
	else if (Protect == PAGE_EXECUTE_READ) {
		StringCchPrintfA(pszBuffer, cBuffer, "r-x");
	}
	else if (Protect == PAGE_EXECUTE_READWRITE) {
		StringCchPrintfA(pszBuffer, cBuffer, "rwx");
	}
	else if (Protect == PAGE_EXECUTE_WRITECOPY) {
		StringCchPrintfA(pszBuffer, cBuffer, "rcx");
	}
	else if (Protect == PAGE_NOACCESS) {
		StringCchPrintfA(pszBuffer, cBuffer, "---");
	}
	else if (Protect == PAGE_READONLY) {
		StringCchPrintfA(pszBuffer, cBuffer, "r--");
	}
	else if (Protect == PAGE_READWRITE) {
		StringCchPrintfA(pszBuffer, cBuffer, "rw-");
	}
	else if (Protect == PAGE_WRITECOPY) {
		StringCchPrintfA(pszBuffer, cBuffer, "rc-");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE)) {
		StringCchPrintfA(pszBuffer, cBuffer, "g--x");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READ)) {
		StringCchPrintfA(pszBuffer, cBuffer, "gr-x");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READWRITE)) {
		StringCchPrintfA(pszBuffer, cBuffer, "grwx");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_WRITECOPY)) {
		StringCchPrintfA(pszBuffer, cBuffer, "grcx");
	}
	else if (Protect == (PAGE_GUARD | PAGE_NOACCESS)) {
		StringCchPrintfA(pszBuffer, cBuffer, "g---");
	}
	else if (Protect == (PAGE_GUARD | PAGE_READONLY)) {
		StringCchPrintfA(pszBuffer, cBuffer, "gr--");
	}
	else if (Protect == (PAGE_GUARD | PAGE_READWRITE)) {
		StringCchPrintfA(pszBuffer, cBuffer, "grw-");
	}
	else if (Protect == (PAGE_GUARD | PAGE_WRITECOPY)) {
		StringCchPrintfA(pszBuffer, cBuffer, "grc-");
	}
	else {
		StringCchPrintfA(pszBuffer, cBuffer, "%x", Protect);
	}
}

typedef union
{
	struct
	{
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
	} ih;

	IMAGE_NT_HEADERS32 ih32;
	IMAGE_NT_HEADERS64 ih64;
} IMAGE_NT_HEADER;

struct SECTIONS
{
	PBYTE   pbBeg;
	PBYTE   pbEnd;
	CHAR    szName[16];
} Sections[256];
DWORD SectionCount = 0;
DWORD Bitness = 0;

PCHAR FindSectionName(PBYTE pbBase, PBYTE& pbEnd)
{
	for (DWORD n = 0; n < SectionCount; n++) {
		if (Sections[n].pbBeg == pbBase) {
			pbEnd = Sections[n].pbEnd;
			return Sections[n].szName;
		}
	}
	pbEnd = NULL;
	return NULL;
}

ULONG PadToPage(ULONG Size)
{
	return (Size & 0xfff)
		? Size + 0x1000 - (Size & 0xfff)
		: Size;
}

BOOL GetSections(HANDLE hp, PBYTE pbBase)
{
	DWORD beg = 0;
	DWORD cnt = 0;
	SIZE_T done;
	IMAGE_DOS_HEADER idh;

	if (!ReadProcessMemory(hp, pbBase, &idh, sizeof(idh), &done) || done != sizeof(idh)) {
		return FALSE;
	}

	if (idh.e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	IMAGE_NT_HEADER inh;
	if (!ReadProcessMemory(hp, pbBase + idh.e_lfanew, &inh, sizeof(inh), &done) || done != sizeof(inh)) {
		printf("No Read\n");
		return FALSE;
	}

	if (inh.ih.Signature != IMAGE_NT_SIGNATURE) {
		printf("No NT\n");
		return FALSE;
	}

	beg = idh.e_lfanew
		+ FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)
		+ inh.ih.FileHeader.SizeOfOptionalHeader;
	cnt = inh.ih.FileHeader.NumberOfSections;
	Bitness = (inh.ih32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 32 : 64;
#if 0
	printf("%d %d count=%d\n", beg, Bitness, cnt);
#endif

	IMAGE_SECTION_HEADER ish;
	for (DWORD n = 0; n < cnt; n++) {
		if (!ReadProcessMemory(hp, pbBase + beg + n * sizeof(ish), &ish, sizeof(ish), &done) || done != sizeof(ish)) {
			printf("No Read\n");
			return FALSE;
		}
		Sections[n].pbBeg = pbBase + ish.VirtualAddress;
		Sections[n].pbEnd = pbBase + ish.VirtualAddress + PadToPage(ish.Misc.VirtualSize);
		memcpy(Sections[n].szName, ish.Name, sizeof(ish.Name));
		Sections[n].szName[sizeof(ish.Name)] = '\0';
#if 0
		printf("--- %p %s\n", Sections[n].pbBeg, Sections[n].szName);
#endif
	}
	SectionCount = cnt;

	return TRUE;
}

BOOL DumpProcess(HANDLE hp)
{
	ULONG64 base;
	ULONG64 next;

	MEMORY_BASIC_INFORMATION mbi;

	printf("  %12s %8s %8s: %3s %3s %4s %3s : %8s\n", "Address", "Offset", "Size", "Typ", "Sta", "Prot", "Ini", "Contents");
	printf("  %12s %8s %8s: %3s %3s %4s %3s : %8s\n", "------------", "--------", "--------", "---", "---", "----", "---", "-----------------");

	for (next = 0;;) {
		base = next;
		ZeroMemory(&mbi, sizeof(mbi));
		if (VirtualQueryEx(hp, (PVOID)base, &mbi, sizeof(mbi)) == 0) {
			break;
		}
		if ((mbi.RegionSize & 0xfff) == 0xfff) {
			break;
		}

		next = (ULONG64)mbi.BaseAddress + mbi.RegionSize;

		if (mbi.State == MEM_FREE) {
			continue;
		}

		CHAR szType[16];
		TypeToString(mbi.Type, szType, ARRAYSIZE(szType));
		CHAR szState[16];
		StateToString(mbi.State, szState, ARRAYSIZE(szState));
		CHAR szProtect[16];
		ProtectToString(mbi.Protect, szProtect, ARRAYSIZE(szProtect));
		CHAR szAllocProtect[16];
		ProtectToString(mbi.AllocationProtect, szAllocProtect, ARRAYSIZE(szAllocProtect));

		CHAR szFile[MAX_PATH];
		szFile[0] = '\0';
		DWORD cb = 0;
		PCHAR pszFile = szFile;

		if (base == (ULONG64)mbi.AllocationBase) {
#if 0
			cb = pfGetMappedFileName(hp, (PVOID)mbi.AllocationBase, szFile, ARRAYSIZE(szFile));
#endif
			if (GetSections(hp, (PBYTE)mbi.AllocationBase)) {
				next = base + 0x1000;
				StringCchPrintfA(szFile, ARRAYSIZE(szFile), "%d-bit PE", Bitness);
			}
		}
		if (cb > 0) {
			for (DWORD c = 0; c < cb; c++) {
				szFile[c] = (szFile[c] >= 'a' && szFile[c] <= 'z')
					? szFile[c] - 'a' + 'A' : szFile[c];
			}
			szFile[cb] = '\0';
		}

		if ((pszFile = strrchr(szFile, '\\')) == NULL) {
			pszFile = szFile;
		}
		else {
			pszFile++;
		}

		PBYTE pbEnd;
		PCHAR pszSect = FindSectionName((PBYTE)base, pbEnd);
		if (pszSect != NULL) {
			pszFile = pszSect;
			if (next > (ULONG64)pbEnd) {
				next = (ULONG64)pbEnd;
			}
		}

		CHAR szDesc[128];
		ZeroMemory(&szDesc, ARRAYSIZE(szDesc));
		if (base == (ULONG64)mbi.AllocationBase) {
			StringCchPrintfA(szDesc, ARRAYSIZE(szDesc), "  %12I64x %8I64x %8I64x: %3s %3s %4s %3s : %s",
				(ULONG64)base,
				(ULONG64)base - (ULONG64)mbi.AllocationBase,
				(ULONG64)next - (ULONG64)base,
				szType,
				szState,
				szProtect,
				szAllocProtect,
				pszFile);


		}
		else {
			StringCchPrintfA(szDesc, ARRAYSIZE(szDesc), "  %12s %8I64x %8I64x: %3s %3s %4s %3s : %s",
				"-",
				(ULONG64)base - (ULONG64)mbi.AllocationBase,
				(ULONG64)next - (ULONG64)base,
				szType,
				szState,
				szProtect,
				szAllocProtect,
				pszFile);
		}
		printf("%s\n", szDesc);
	}
	return TRUE;
}

//////////////////////////////////////////////////////////////////////// main.
//
int CDECL main(int argc, char** argv)
{
	BOOLEAN fNeedHelp = FALSE;
	BOOLEAN fVerbose = FALSE;
	LPCSTR rpszDllsRaw[1];
	LPCSTR rpszDllsOut[1];
	DWORD nDlls = 1;
	uint32_t blockTime = 0;

	for (DWORD n = 0; n < ARRAYSIZE(rpszDllsRaw); n++) {
		rpszDllsRaw[n] = NULL;
		rpszDllsOut[n] = NULL;
	}
	rpszDllsRaw[0] = DLLNAME;
	int arg = 1;
	for (; arg < argc && (argv[arg][0] == '-' || argv[arg][0] == '/'); arg++) {

		CHAR* argn = argv[arg] + 1;
		CHAR* argp = argn;
		while (*argp && *argp != ':' && *argp != '=')
			argp++;
		if (*argp == ':' || *argp == '=')
			*argp++ = '\0';

		switch (argn[0]) {
		case 't':
		case 'T':
			blockTime = std::stoi(std::string(argp));
			SetEnvironmentVariable(L"quality-block-time",std::to_wstring(blockTime).c_str());
			break;
		case 'v':                                     // Verbose
		case 'V':
			fVerbose = TRUE;
			break;

		case '?':                                     // Help
			fNeedHelp = TRUE;
			break;

		default:
			fNeedHelp = TRUE;
			printf("Error: Bad argument: %s\n", argv[arg]);
			break;
		}
	}

	if (arg >= argc) {
		fNeedHelp = TRUE;
	}

	if (nDlls == 0) {
		fNeedHelp = TRUE;
	}

	if (fNeedHelp) {
		PrintUsage();
		return 9001;
	}

	/////////////////////////////////////////////////////////// Validate DLLs.
	//
	for (DWORD n = 0; n < nDlls; n++) {
		CHAR szDllPath[1024];
		PCHAR pszFilePart = NULL;

		if (!GetFullPathNameA(rpszDllsRaw[n], ARRAYSIZE(szDllPath), szDllPath, &pszFilePart)) {
			printf("Error: %s is not a valid path name..\n",
				rpszDllsRaw[n]);
			return 9002;
		}

		DWORD c = (DWORD)strlen(szDllPath) + 1;
		PCHAR psz = new CHAR[c];
		StringCchCopyA(psz, c, szDllPath);
		rpszDllsOut[n] = psz;

		HMODULE hDll = LoadLibraryExA(rpszDllsOut[n], NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (hDll == NULL) {
			printf("Error: %s failed to load (error %ld).\n",
				rpszDllsOut[n],
				GetLastError());
			return 9003;
		}

		ExportContext ec;
		ec.fHasOrdinal1 = FALSE;
		ec.nExports = 0;
		DetourEnumerateExports(hDll, &ec, ExportCallback);
		FreeLibrary(hDll);

		if (!ec.fHasOrdinal1) {
			printf("Error: %s does not export ordinal #1.\n",
				rpszDllsOut[n]);
			printf("See help entry DetourCreateProcessWithDllEx in Detours.chm.\n");
			return 9004;
		}
	}

	//////////////////////////////////////////////////////////////////////////
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	CHAR szCommand[2048];
	CHAR szExe[1024];
	CHAR szFullExe[1024] = "\0";
	PCHAR pszFileExe = NULL;

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	szCommand[0] = L'\0';

	StringCchCopyA(szExe, sizeof(szExe), argv[arg]);
	for (; arg < argc; arg++) {
		if (strchr(argv[arg], ' ') != NULL || strchr(argv[arg], '\t') != NULL) {
			StringCchCatA(szCommand, sizeof(szCommand), "\"");
			StringCchCatA(szCommand, sizeof(szCommand), argv[arg]);
			StringCchCatA(szCommand, sizeof(szCommand), "\"");
		}
		else {
			StringCchCatA(szCommand, sizeof(szCommand), argv[arg]);
		}

		if (arg + 1 < argc) {
			StringCchCatA(szCommand, sizeof(szCommand), " ");
		}
	}
	printf("Starting: `%s'\n", szCommand);
	for (DWORD n = 0; n < nDlls; n++) {
		printf("with `%s'\n", rpszDllsOut[n]);
	}
	fflush(stdout);

	DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;

	SetLastError(0);
	SearchPathA(NULL, szExe, ".exe", ARRAYSIZE(szFullExe), szFullExe, &pszFileExe);
	if (!DetourCreateProcessWithDllsA(szFullExe[0] ? szFullExe : NULL, szCommand,
		NULL, NULL, TRUE, dwFlags, NULL, NULL,
		&si, &pi, nDlls, rpszDllsOut, NULL)) {
		DWORD dwError = GetLastError();
		printf("DetourCreateProcessWithDllEx failed: %ld\n", dwError);
		if (dwError == ERROR_INVALID_HANDLE) {
#if DETOURS_64BIT
			printf("Can't detour a 32-bit target process from a 64-bit parent process.\n");
#else
			printf("Can't detour a 64-bit target process from a 32-bit parent process.\n");
#endif
		}
		ExitProcess(9009);
	}

	if (fVerbose) {
		DumpProcess(pi.hProcess);
	}

	ResumeThread(pi.hThread);

	return 0;
}
//
///////////////////////////////////////////////////////////////// End of File.
