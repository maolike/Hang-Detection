// parseCallStack.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <DbgHelp.h>
#include <locale>
#include <codecvt>
#include "callstackdef.h"
#include "json.hpp"
#include <fstream>
#include <rpcdce.h>
#include <Urlmon.h>
#pragma comment(lib, "dbghelp.lib")  
#pragma comment(lib, "Rpcrt4.lib")  
#pragma comment(lib,"Urlmon.lib")

#define PDBDIR L"pdb"

std::vector<std::wstring> symbolServers = {
	L"https://msdl.microsoft.com/download/symbols",
	L"http://127.0.0.1:8001"
};

std::wstring parseFrame(const std::string& ImageName ,const std::string& PdbName,const std::string& PdbSig70,DWORD offset)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring wImageName = converter.from_bytes(ImageName);
	std::wstring wPdbName = converter.from_bytes(PdbName);
	std::wstring wPdbSig70 = converter.from_bytes(PdbSig70);
	std::wstring wOffset = converter.from_bytes(callstack::Utils::n2hexstr(offset));

	std::wstring resolveStr = wImageName + std::wstring(L"[0x") + wOffset + std::wstring(L"]");

	std::wstring pdbPath = L"pdb/" + wPdbName;
	std::ifstream f(pdbPath.c_str());
	if (!f.good())
	{
		bool b = false;
		for(const std::wstring& symbolServer : symbolServers)
		{
			std::wstring downloadUrl = symbolServer + L"/" + wPdbName + L"/" + wPdbSig70 + L"/" + wPdbName;
			HRESULT hr = URLDownloadToFile(NULL, downloadUrl.c_str(), pdbPath.c_str(), NULL, NULL);
			if (SUCCEEDED(hr))
			{
				b = true;
				break;
			}
		}

		if (!b)
		{
			printf("Failed to download pdb:%ls.\n", wPdbName.c_str());
			return resolveStr;
		}
	}
	
	WCHAR* path = const_cast<WCHAR*>(pdbPath.c_str());
	HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	DWORD dwFileSize = GetFileSize(hFile, nullptr);
	static DWORD64 inputBaseAddress = 0x10000000;
	DWORD64 dwBaseAddress = SymLoadModuleExW(GetCurrentProcess(), NULL, path, NULL, inputBaseAddress, dwFileSize, NULL, 0);
	inputBaseAddress += 0x1000000;
	if (dwBaseAddress == 0) {
		printf("Failed to load module:%ls.\n", wImageName.c_str());
		return resolveStr;
	}
	DWORD64 baseAdd = dwBaseAddress;
	DWORD64 dwAddress = baseAdd + offset; // 指定的地址  

	IMAGEHLP_LINEW64 line;
	DWORD dwDisplacement = 0;
	line.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);

	std::wstring lineInfo;
	if (SymGetLineFromAddrW64(GetCurrentProcess(), dwAddress, &dwDisplacement, &line)) {
		wprintf(L"File: %s\nLine: %d\n", line.FileName, line.LineNumber);
		lineInfo = L" " + std::wstring(line.FileName) + L":" + std::to_wstring(line.LineNumber) + L"  ";
	}
	else {
		printf("Failed to get line information.module:%ls\n", wImageName.c_str());
	}


	DWORD64 dwDisplacement2 = 0;
	char buffer[sizeof(PIMAGEHLP_SYMBOL64) + MAX_SYM_NAME * sizeof(TCHAR)];
	PIMAGEHLP_SYMBOL64 pSymbol = (PIMAGEHLP_SYMBOL64)buffer;

	pSymbol->SizeOfStruct = sizeof(PIMAGEHLP_SYMBOL64);
	pSymbol->MaxNameLength = MAX_SYM_NAME;
	std::wstring symNameInfo;
	if (SymGetSymFromAddr64(GetCurrentProcess(), dwAddress, &dwDisplacement2, pSymbol))
	{
		printf("symbol:%s\n", pSymbol->Name);
		std::wstring wNmae = converter.from_bytes(pSymbol->Name);
		symNameInfo = wNmae + L" ";
	}
	else
	{
		printf("Failed to get symbol name.module:%ls\n", wImageName.c_str());
	}

	return symNameInfo + lineInfo + resolveStr;
}

int main()
{
	CreateDirectory(PDBDIR, NULL);
	HANDLE hProcess = ::GetCurrentProcess();
	if (SymInitialize(hProcess, NULL, TRUE) == FALSE)
		return 1;
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
	
	TCHAR lpTempPathBuffer[MAX_PATH];
	DWORD dwRetVal = 0;
	dwRetVal = ::GetTempPath(MAX_PATH, lpTempPathBuffer);
	if (dwRetVal > MAX_PATH || (dwRetVal == 0))
		return 1;
	std::wstring tempDir = lpTempPathBuffer;

	using json = nlohmann::json;
	std::ifstream f(tempDir + L"/hangs.log");
	std::string line;
	while (std::getline(f, line))
	{
		json data=json::parse(line);
		std::string uuid = data["uuid"];
		std::ifstream f("quality-block-"+uuid);
		if(f.good())
			continue;
		std::wstring strFrames = L"";
		json allFrames = data["allFrame"];
		for (unsigned int i = 0; i < allFrames.size(); ++i)
		{
			json frame = allFrames[i];
			std::string img = frame["ImageName"];
			DWORD offset = frame["offset"];
			std::string pdb = data["allImage"][img]["CVData"];
			std::string pdbSig70 = data["allImage"][img]["PdbSig70"];
			strFrames += parseFrame(img, pdb, pdbSig70, offset);
			strFrames += L"\n";
		}

		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
		std::wstring wGuid = converter.from_bytes(uuid);
		std::wstring file = L"hang-" + wGuid;
		std::wofstream newFile(file);
		newFile << strFrames << std::endl;
		newFile.close();
	}

	SymCleanup(hProcess);
	return 0;
}
