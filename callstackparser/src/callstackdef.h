#pragma once

#include <windows.h>
#include <sstream>
#include "json.hpp"

namespace callstack
{

struct ImageInfo
{
    std::string ImageName;
    std::string CVData;
    unsigned long ImageSize;
    std::string PdbSig70;
};

struct StackFrame
{
    std::string ImageName;
    unsigned int offset;
};

struct StackWalkResult
{
    std::map<std::string, ImageInfo> allImage;
    std::vector<StackFrame> allFrame;
    std::string chainId;
    std::string timePoint;
    int hangTime;
    unsigned int message;
};

class Utils
{
public:
	template <typename I>
	static std::string n2hexstr(I w, bool autoZero = true, size_t hex_len = sizeof(I) << 1)
	{
		static const char* digits = "0123456789ABCDEF";
		std::string rc(hex_len, '0');
		for (size_t i = 0, j = (hex_len - 1) * 4; i < hex_len; ++i, j -= 4)
			rc[i] = digits[(w >> j) & 0x0f];
		if (autoZero)
			return rc;
		size_t i = 0;
		for (; i < hex_len && rc[i] == '0'; ++i)
			;
		if (i >= rc.size())
			return "";
		return rc.substr(i);
	}

	static std::string toString(const GUID& PdbSig70, DWORD PdbAge)
	{
		std::string res = n2hexstr(PdbSig70.Data1) + n2hexstr(PdbSig70.Data2) + n2hexstr(PdbSig70.Data3);
		for (int i = 0; i < ARRAYSIZE(PdbSig70.Data4); ++i)
		{
			res += n2hexstr(PdbSig70.Data4[i]);
		}
		return res += n2hexstr(PdbAge, false);
	}
};
} // namespace callstack
