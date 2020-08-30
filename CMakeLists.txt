project(ProcessHollowing)
cmake_minimum_required(VERSION 3.1)

add_executable(ProcessHollowing
    ProcessHollowing.cpp
	DLLFunctionsLoader.cpp
    DLLFunctionsLoader.hpp
    NtdllFunctions.cpp
    NtdllFunctions.hpp
    ProcedurePointer.cpp
    ProcedurePointer.hpp
)