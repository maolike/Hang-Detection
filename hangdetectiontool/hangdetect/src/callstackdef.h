#pragma once

#include <windows.h>
#include <sstream>
#include "json.hpp"
#pragma comment(lib, "Rpcrt4.lib") 

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
	int stackWalkTime;
    unsigned int message;
};

class Utils
{
public:
	static std::string toJsonString(const StackWalkResult& result)
	{
		using json = nlohmann::json;
		json ret;
		ret["chainId"] = result.chainId;
		ret["hangTime"] = result.hangTime;
		ret["timePoint"] = result.timePoint;
		ret["stackWalkTime"] = result.stackWalkTime;

		UUID uuid;
		UuidCreate(&uuid);
		char* strUuid;
		UuidToStringA(&uuid, (RPC_CSTR*)&strUuid);
		ret["uuid"] = strUuid;
		RpcStringFreeA((RPC_CSTR*)&strUuid);

		ret["message"] = result.message;
		json frames;
		for (size_t i = 0; i < result.allFrame.size(); ++i)
		{
			json frame;
			frame["ImageName"] = result.allFrame[i].ImageName;
			frame["offset"] = result.allFrame[i].offset;
			frames[i] = frame;		
		}
		ret["allFrame"] = frames;

		json images;
		for (std::map<std::string, ImageInfo>::const_iterator pos = result.allImage.begin(); pos != result.allImage.end(); ++pos)
		{
			json image;
			image["ImageSize"] = (unsigned int)pos->second.ImageSize;
			image["CVData"] = pos->second.CVData;
			image["PdbSig70"] = pos->second.PdbSig70;

			images[pos->second.ImageName] = image;
		}
		ret["allImage"] = images;
		return ret.dump();
	}

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
