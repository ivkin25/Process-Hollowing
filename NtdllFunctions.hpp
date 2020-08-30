#pragma once

#include <Windows.h>
#include <string>
#include <winternl.h>
#include "DLLFunctionsLoader.hpp"

class NtdllFunctions
{
public:
    //Enter ntdll functions here

private:
    static DLLFunctionsLoader _functionsLoader;
};