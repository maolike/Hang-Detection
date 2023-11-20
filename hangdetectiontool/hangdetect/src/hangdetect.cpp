// blockDetect.cpp : 定义静态库的函数。
//

#include "hangdetect.h"
#include "threadhangmonitor.h"

uint32_t g_hangTime = 2000;
void HANGDETECT::start()
{
	ThreadHangMonitor::Instance()->init();
	std::vector<unsigned int> msg;
	msg.push_back(WM_NCLBUTTONDOWN);
	ThreadHangMonitor::Instance()->monitorMsg(msg);
}

void HANGDETECT::setHangTime(uint32_t t)
{
	g_hangTime = t;
}

uint32_t HANGDETECT::getHangTime()
{
	return g_hangTime;
}

void HANGDETECT::stop()
{
	ThreadHangMonitor::Instance()->release();
}
