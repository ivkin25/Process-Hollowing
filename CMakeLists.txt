project(ProcessHollowing)
cmake_minimum_required(VERSION 3.1)

file(GLOB ProcessHollowing_SRC
    "*.hpp"
    "*.cpp"
    "exceptions/*.hpp"
    "exceptions/*.cpp"
)

# Set for debug messages
set(DEBUG_MODE OFF)

if(DEBUG_MODE)
    add_definitions(-D_DEBUG_MODE)
endif()

add_executable(ProcessHollowing ${ProcessHollowing_SRC})