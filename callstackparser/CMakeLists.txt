cmake_minimum_required(VERSION 3.10) 

project(callstackparser) 

set(CMAKE_CXX_STANDARD 14) 
set(CMAKE_CXX_STANDARD_REQUIRED True) 

# add the executable 
add_executable(${PROJECT_NAME} src/main.cpp) 
target_sources(callstackparser
PUBLIC src/json.hpp
PUBLIC src/callstackdef.h)

#设置可执行目标文件的输出目录
set_target_properties(callstackparser PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

add_definitions(-DUNICODE -D_UNICODE)
