message(STATUS "-------------begin  launchWithHangdetect cmake-----------")

cmake_minimum_required(VERSION 3.26) 
#set(CMAKE_GENERATOR_PLATFORM win32)

project(launchWithHangdetect) 

set(CMAKE_CXX_STANDARD 14) 
set(CMAKE_CXX_STANDARD_REQUIRED True) 

# add the executable 
add_executable(${PROJECT_NAME} src/launchWithHangDetect.cpp) 

#设置可执行目标文件的输出目录
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

#unicode
add_definitions(-DUNICODE -D_UNICODE)

#加一个子目录
add_subdirectory(detours)
add_subdirectory(hangdetect)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/detours/src)

#链接
target_link_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/detours/bin/Debug)
target_link_libraries(${PROJECT_NAME} detours)
message(STATUS "-------------end  launchWithHangdetect cmake-----------")