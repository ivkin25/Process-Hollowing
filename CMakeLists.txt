project(ProcessHollowing)
cmake_minimum_required(VERSION 3.1)

file(GLOB ProcessHollowing_SRC
    "*.hpp"
    "*.cpp"
)

add_executable(ProcessHollowing ${ProcessHollowing_SRC})