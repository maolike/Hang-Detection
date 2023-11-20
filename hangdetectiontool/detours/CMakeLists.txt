message(STATUS "-------------begin  detours cmake-----------")
cmake_minimum_required(VERSION 3.26)
#set(CMAKE_GENERATOR_PLATFORM win32)

project(detours)
add_library(${PROJECT_NAME} src/creatwth.cpp
src/detours.cpp
src/disasm.cpp
src/disolarm.cpp
src/disolarm64.cpp
src/disolia64.cpp
src/disolx64.cpp
src/disolx86.cpp
src/image.cpp
src/modules.cpp
) 

#Visual Studio要这么写才生效
set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)
message(STATUS "-------------end  detours cmake-----------")