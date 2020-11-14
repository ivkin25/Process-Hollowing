#pragma once

#include <Windows.h>
#include <string>
#include "DLLFunctionsLoader.hpp"

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation             = 0x00,
    ProcessQuotaLimits              = 0x01,
    ProcessIoCounters               = 0x02,
    ProcessVmCounters               = 0x03,
    ProcessTimes                = 0x04,
    ProcessBasePriority             = 0x05,
    ProcessRaisePriority            = 0x06,
    ProcessDebugPort                = 0x07,
    ProcessExceptionPort            = 0x08,
    ProcessAccessToken              = 0x09,
    ProcessLdtInformation               = 0x0A,
    ProcessLdtSize                  = 0x0B,
    ProcessDefaultHardErrorMode         = 0x0C,
    ProcessIoPortHandlers               = 0x0D,
    ProcessPooledUsageAndLimits         = 0x0E,
    ProcessWorkingSetWatch              = 0x0F,
    ProcessUserModeIOPL             = 0x10,
    ProcessEnableAlignmentFaultFixup        = 0x11,
    ProcessPriorityClass            = 0x12,
    ProcessWx86Information              = 0x13,
    ProcessHandleCount              = 0x14,
    ProcessAffinityMask             = 0x15,
    ProcessPriorityBoost            = 0x16,
    ProcessDeviceMap                = 0x17,
    ProcessSessionInformation           = 0x18,
    ProcessForegroundInformation        = 0x19,
    ProcessWow64Information             = 0x1A,
    ProcessImageFileName            = 0x1B,
    ProcessLUIDDeviceMapsEnabled        = 0x1C,
    ProcessBreakOnTermination           = 0x1D,
    ProcessDebugObjectHandle            = 0x1E,
    ProcessDebugFlags               = 0x1F,
    ProcessHandleTracing            = 0x20,
    ProcessIoPriority               = 0x21,
    ProcessExecuteFlags             = 0x22,
    ProcessResourceManagement           = 0x23,
    ProcessCookie                   = 0x24,
    ProcessImageInformation             = 0x25,
    ProcessCycleTime                = 0x26,
    ProcessPagePriority             = 0x27,
    ProcessInstrumentationCallback          = 0x28,
    ProcessThreadStackAllocation        = 0x29,
    ProcessWorkingSetWatchEx            = 0x2A,
    ProcessImageFileNameWin32           = 0x2B,
    ProcessImageFileMapping             = 0x2C,
    ProcessAffinityUpdateMode           = 0x2D,
    ProcessMemoryAllocationMode         = 0x2E,
    ProcessGroupInformation             = 0x2F,
    ProcessTokenVirtualizationEnabled       = 0x30,
    ProcessConsoleHostProcess           = 0x31,
    ProcessWindowInformation            = 0x32,
    ProcessHandleInformation            = 0x33,
    ProcessMitigationPolicy             = 0x34,
    ProcessDynamicFunctionTableInformation      = 0x35,
    ProcessHandleCheckingMode           = 0x36,
    ProcessKeepAliveCount               = 0x37,
    ProcessRevokeFileHandles            = 0x38,
    ProcessWorkingSetControl            = 0x39,
    ProcessHandleTable              = 0x3A,
    ProcessCheckStackExtentsMode        = 0x3B,
    ProcessCommandLineInformation           = 0x3C,
    ProcessProtectionInformation        = 0x3D,
    ProcessMemoryExhaustion             = 0x3E,
    ProcessFaultInformation             = 0x3F,
    ProcessTelemetryIdInformation           = 0x40,
    ProcessCommitReleaseInformation         = 0x41,
    ProcessDefaultCpuSetsInformation        = 0x42,
    ProcessAllowedCpuSetsInformation        = 0x43,
    ProcessSubsystemProcess             = 0x44,
    ProcessJobMemoryInformation         = 0x45,
    ProcessInPrivate                = 0x46,
    ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
    ProcessIumChallengeResponse         = 0x48,
    ProcessChildProcessInformation          = 0x49,
    ProcessHighGraphicsPriorityInformation      = 0x4A,
    ProcessSubsystemInformation         = 0x4B,
    ProcessEnergyValues             = 0x4C,
    ProcessActivityThrottleState        = 0x4D,
    ProcessActivityThrottlePolicy           = 0x4E,
    ProcessWin32kSyscallFilterInformation       = 0x4F,
    ProcessDisableSystemAllowedCpuSets      = 0x50,
    ProcessWakeInformation              = 0x51,
    ProcessEnergyTrackingState          = 0x52,
    ProcessManageWritesToExecutableMemory       = 0x53,
    ProcessCaptureTrustletLiveDump          = 0x54,
    ProcessTelemetryCoverage            = 0x55,
    ProcessEnclaveInformation           = 0x56,
    ProcessEnableReadWriteVmLogging         = 0x57,
    ProcessUptimeInformation            = 0x58,
    ProcessImageSection             = 0x59,
    ProcessDebugAuthInformation         = 0x5A,
    ProcessSystemResourceManagement         = 0x5B,
    ProcessSequenceNumber               = 0x5C,
    ProcessLoaderDetour             = 0x5D,
    ProcessSecurityDomainInformation        = 0x5E,
    ProcessCombineSecurityDomainsInformation    = 0x5F,
    ProcessEnableLogging            = 0x60,
    ProcessLeapSecondInformation        = 0x61,
    ProcessFiberShadowStackAllocation       = 0x62,
    ProcessFreeFiberShadowStackAllocation       = 0x63,
    MaxProcessInfoClass             = 0x64
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY
    ThreadBasePriority, // s: LONG
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress, // q: PVOID
    ThreadZeroTlsCell, // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState,
    ThreadIsTerminated, // q: ULONG // 20
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: IO_PRIORITY_HINT
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority, // q: ULONG
    ThreadActualBasePriority,
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context, // q: WOW64_CONTEXT
    ThreadGroupInformation, // q: GROUP_AFFINITY // 30
    ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
    ThreadCounterProfiling,
    ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
    ThreadCpuAccountingInformation, // since WIN8
    ThreadSuspendCount, // since WINBLUE
    ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, // q: GUID
    ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity, // since THRESHOLD2
    ThreadDynamicCodePolicyInfo,
    ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
    ThreadWorkOnBehalfTicket,
    ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive,
    ThreadAttachContainer,
    ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState, // THREAD_POWER_THROTTLING_STATE
    ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef NTSTATUS (NTAPI *NtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS (NTAPI *NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext);
typedef NTSTATUS (NTAPI *NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead);
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS (NTAPI *NtSetContextThread)(HANDLE ThreadHanble, PCONTEXT Context);
typedef NTSTATUS (NTAPI *NtResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);
typedef NTSTATUS (NTAPI *NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

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
    static NtQueryInformationThread _NtQueryInformationThread;

private:
    static DLLFunctionsLoader _functionsLoader;
};