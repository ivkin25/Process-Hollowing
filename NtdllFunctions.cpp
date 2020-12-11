#include "NtdllFunctions.hpp"

const LPCSTR NTDLL_DLL_NAME = "ntdll.dll";

DLLFunctionsLoader NtdllFunctions::_functionsLoader(NTDLL_DLL_NAME);
NtQueryInformationProcess NtdllFunctions::_NtQueryInformationProcess = (NtQueryInformationProcess)(NtdllFunctions::_functionsLoader["NtQueryInformationProcess"]);
NtGetContextThread NtdllFunctions::_NtGetContextThread = NtdllFunctions::_functionsLoader["NtGetContextThread"];
NtReadVirtualMemory NtdllFunctions::_NtReadVirtualMemory = NtdllFunctions::_functionsLoader["NtReadVirtualMemory"];
NtUnmapViewOfSection NtdllFunctions::_NtUnmapViewOfSection = NtdllFunctions::_functionsLoader["NtUnmapViewOfSection"];
NtWriteVirtualMemory NtdllFunctions::_NtWriteVirtualMemory = NtdllFunctions::_functionsLoader["NtWriteVirtualMemory"];
NtSetContextThread NtdllFunctions::_NtSetContextThread = NtdllFunctions::_functionsLoader["NtSetContextThread"];
NtResumeThread NtdllFunctions::_NtResumeThread = NtdllFunctions::_functionsLoader["NtResumeThread"];
NtQueryInformationThread NtdllFunctions::_NtQueryInformationThread = NtdllFunctions::_functionsLoader["NtQueryInformationThread"];