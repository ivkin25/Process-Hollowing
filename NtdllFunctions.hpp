#pragma once

#include <Windows.h>
#include <string>
#include "DLLFunctionsLoader.hpp"

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef NTSTATUS (NTAPI *NtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS (NTAPI *NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext);
typedef NTSTATUS (NTAPI *NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead);
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS (NTAPI *NtSetContextThread)(HANDLE ThreadHanble, PCONTEXT Context);
typedef NTSTATUS (NTAPI *NtResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);

class NtdllFunctions
{
public:
    static NtQueryInformationProcess _NtQueryInformationProcess;
    static NtGetContextThread _NtGetContextThread;
    static NtReadVirtualMemory _NtReadVirtualMemory;
    static NtUnmapViewOfSection _NtUnmapViewOfSection;
    static NtWriteVirtualMemory _NtWriteVirtualMemory;
    static NtSetContextThread _NtSetContextThread;
    static NtResumeThread _NtResumeThread;

private:
    static DLLFunctionsLoader _functionsLoader;
};