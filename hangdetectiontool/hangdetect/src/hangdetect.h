#pragma once

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#include <stdint.h>
namespace HANGDETECT
{
	void start();
	void setHangTime(uint32_t t);
	uint32_t getHangTime();
	void stop();
}
