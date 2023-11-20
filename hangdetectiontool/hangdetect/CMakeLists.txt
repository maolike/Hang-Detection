message(STATUS "-------------begin  hangdetect cmake-----------")
cmake_minimum_required(VERSION 3.26)
#set(CMAKE_GENERATOR_PLATFORM win32)

project(hangdetect)

# SHARED 动态库
add_library(${PROJECT_NAME} SHARED src/hangdetect.cpp
src/dllmain.cpp
src/stackwalkhelper.cpp
src/threadhangmonitor.cpp
src/threadhangmonitor.h
src/callstackdef.h
src/hangdetect.h
src/stackwalkhelper.h
)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/detours/src)

#output dir On Windows, unlike other platforms, 
#you should use RUNTIME_OUTPUT_DIRECTORY instead of LIBRARY_OUTPUT_DIRECTORY to specify the output directory of a shared library.
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY  "${CMAKE_SOURCE_DIR}/bin"
)

#链接
target_link_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/detours/bin/Release)
target_link_libraries(${PROJECT_NAME} detours)

#一定要导出这个符号
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES LINK_FLAGS /EXPORT:DetourFinishHelperProcess)

message(STATUS "-------------end  hangdetect cmake-----------")