#include "NtdllFunctions.hpp"

const LPCSTR NTDLL_DLL_NAME = "ntdll.dll";

DLLFunctionsLoader NtdllFunctions::_functionsLoader(NTDLL_DLL_NAME);