project(ProcessHollowing)
cmake_minimum_required(VERSION 3.1)

# Set for debug messages
set(DEBUG_MODE OFF)
# x64 Can hollow 64- and 32-bit images, while x86 can only hollow
# 32-bit images
set(BUILD_64_BIT ON)

file(GLOB ProcessHollowing_SRC
    "*.hpp"
    "*.cpp"
    "exceptions/*.hpp"
    "exceptions/*.cpp"
)

if(NOT BUILD_64_BIT)
    list(REMOVE_ITEM ProcessHollowing_SRC "${CMAKE_SOURCE_DIR}/Hollowing64Bit.hpp" "${CMAKE_SOURCE_DIR}/Hollowing64Bit.cpp")
endif()

if(DEBUG_MODE)
    add_definitions(-D_DEBUG_MODE)
endif()

add_executable(ProcessHollowing ${ProcessHollowing_SRC})

if(NOT BUILD_64_BIT)
    set_target_properties(ProcessHollowing PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()