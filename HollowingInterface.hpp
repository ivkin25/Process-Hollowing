#define _WIN32_WINNT 0x0600 // Defined for using functions that were
                            // introduced in Windows Vista / Server 2008

#ifndef HOLLOWING_FUNCTIONS_H
#define HOLLOWING_FUNCTIONS_H

#include <Windows.h>
#include <string>
#include <Ntsecapi.h>
#include <DbgHelp.h>
#include <iostream>
#include "NtdllFunctions.hpp"
#include "exceptions/HollowingException.hpp"
#include "exceptions/FileException.hpp"

//0x10 bytes (sizeof)
struct _STRING64
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    ULONGLONG Buffer;                                                       //0x8
};

//0x8 bytes (sizeof)
struct _STRING32
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    ULONG Buffer;                                                           //0x4
};

//0x7c8 bytes (sizeof)
typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    ULONGLONG Ldr;                                                          //0x18
    ULONGLONG ProcessParameters;                                            //0x20
    ULONGLONG SubSystemData;                                                //0x28
    ULONGLONG ProcessHeap;                                                  //0x30
    ULONGLONG FastPebLock;                                                  //0x38
    ULONGLONG AtlThunkSListPtr;                                             //0x40
    ULONGLONG IFEOKey;                                                      //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob:1;                                           //0x50
            ULONG ProcessInitializing:1;                                    //0x50
            ULONG ProcessUsingVEH:1;                                        //0x50
            ULONG ProcessUsingVCH:1;                                        //0x50
            ULONG ProcessUsingFTH:1;                                        //0x50
            ULONG ProcessPreviouslyThrottled:1;                             //0x50
            ULONG ProcessCurrentlyThrottled:1;                              //0x50
            ULONG ProcessImagesHotPatched:1;                                //0x50
            ULONG ReservedBits0:24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        ULONGLONG KernelCallbackTable;                                      //0x58
        ULONGLONG UserSharedInfoPtr;                                        //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    ULONGLONG ApiSetMap;                                                    //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    ULONGLONG TlsBitmap;                                                    //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    ULONGLONG ReadOnlySharedMemoryBase;                                     //0x88
    ULONGLONG SharedData;                                                   //0x90
    ULONGLONG ReadOnlyStaticServerData;                                     //0x98
    ULONGLONG AnsiCodePageData;                                             //0xa0
    ULONGLONG OemCodePageData;                                              //0xa8
    ULONGLONG UnicodeCaseTableData;                                         //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    ULONGLONG ProcessHeaps;                                                 //0xf0
    ULONGLONG GdiSharedHandleTable;                                         //0xf8
    ULONGLONG ProcessStarterHelper;                                         //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    ULONGLONG LoaderLock;                                                   //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    ULONGLONG PostProcessInitRoutine;                                       //0x230
    ULONGLONG TlsExpansionBitmap;                                           //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    ULONGLONG pShimData;                                                    //0x2d8
    ULONGLONG AppCompatInfo;                                                //0x2e0
    struct _STRING64 CSDVersion;                                            //0x2e8
    ULONGLONG ActivationContextData;                                        //0x2f8
    ULONGLONG ProcessAssemblyStorageMap;                                    //0x300
    ULONGLONG SystemDefaultActivationContextData;                           //0x308
    ULONGLONG SystemAssemblyStorageMap;                                     //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    ULONGLONG SparePointers[4];                                             //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    ULONGLONG WerRegistrationData;                                          //0x358
    ULONGLONG WerShipAssertPtr;                                             //0x360
    ULONGLONG pUnused;                                                      //0x368
    ULONGLONG pImageHeaderHash;                                             //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x378
            ULONG CritSecTracingEnabled:1;                                  //0x378
            ULONG LibLoaderTracingEnabled:1;                                //0x378
            ULONG SpareTracingBits:29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct LIST_ENTRY64 TppWorkerpList;                                     //0x390
    ULONGLONG WaitOnAddressHashTable[128];                                  //0x3a0
    ULONGLONG TelemetryCoverageHeader;                                      //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    ULONGLONG LeapSecondData;                                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x7c0
            ULONG Reserved:31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
} PEB64; 

//0x480 bytes (sizeof)
typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    ULONG Mutant;                                                           //0x4
    ULONG ImageBaseAddress;                                                 //0x8
    ULONG Ldr;                                                              //0xc
    ULONG ProcessParameters;                                                //0x10
    ULONG SubSystemData;                                                    //0x14
    ULONG ProcessHeap;                                                      //0x18
    ULONG FastPebLock;                                                      //0x1c
    ULONG AtlThunkSListPtr;                                                 //0x20
    ULONG IFEOKey;                                                          //0x24
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob:1;                                           //0x28
            ULONG ProcessInitializing:1;                                    //0x28
            ULONG ProcessUsingVEH:1;                                        //0x28
            ULONG ProcessUsingVCH:1;                                        //0x28
            ULONG ProcessUsingFTH:1;                                        //0x28
            ULONG ProcessPreviouslyThrottled:1;                             //0x28
            ULONG ProcessCurrentlyThrottled:1;                              //0x28
            ULONG ProcessImagesHotPatched:1;                                //0x28
            ULONG ReservedBits0:24;                                         //0x28
        };
    };
    union
    {
        ULONG KernelCallbackTable;                                          //0x2c
        ULONG UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved;                                                   //0x30
    ULONG AtlThunkSListPtr32;                                               //0x34
    ULONG ApiSetMap;                                                        //0x38
    ULONG TlsExpansionCounter;                                              //0x3c
    ULONG TlsBitmap;                                                        //0x40
    ULONG TlsBitmapBits[2];                                                 //0x44
    ULONG ReadOnlySharedMemoryBase;                                         //0x4c
    ULONG SharedData;                                                       //0x50
    ULONG ReadOnlyStaticServerData;                                         //0x54
    ULONG AnsiCodePageData;                                                 //0x58
    ULONG OemCodePageData;                                                  //0x5c
    ULONG UnicodeCaseTableData;                                             //0x60
    ULONG NumberOfProcessors;                                               //0x64
    ULONG NtGlobalFlag;                                                     //0x68
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
    ULONG HeapSegmentReserve;                                               //0x78
    ULONG HeapSegmentCommit;                                                //0x7c
    ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
    ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
    ULONG NumberOfHeaps;                                                    //0x88
    ULONG MaximumNumberOfHeaps;                                             //0x8c
    ULONG ProcessHeaps;                                                     //0x90
    ULONG GdiSharedHandleTable;                                             //0x94
    ULONG ProcessStarterHelper;                                             //0x98
    ULONG GdiDCAttributeList;                                               //0x9c
    ULONG LoaderLock;                                                       //0xa0
    ULONG OSMajorVersion;                                                   //0xa4
    ULONG OSMinorVersion;                                                   //0xa8
    USHORT OSBuildNumber;                                                   //0xac
    USHORT OSCSDVersion;                                                    //0xae
    ULONG OSPlatformId;                                                     //0xb0
    ULONG ImageSubsystem;                                                   //0xb4
    ULONG ImageSubsystemMajorVersion;                                       //0xb8
    ULONG ImageSubsystemMinorVersion;                                       //0xbc
    ULONG ActiveProcessAffinityMask;                                        //0xc0
    ULONG GdiHandleBuffer[34];                                              //0xc4
    ULONG PostProcessInitRoutine;                                           //0x14c
    ULONG TlsExpansionBitmap;                                               //0x150
    ULONG TlsExpansionBitmapBits[32];                                       //0x154
    ULONG SessionId;                                                        //0x1d4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
    ULONG pShimData;                                                        //0x1e8
    ULONG AppCompatInfo;                                                    //0x1ec
    struct _STRING32 CSDVersion;                                            //0x1f0
    ULONG ActivationContextData;                                            //0x1f8
    ULONG ProcessAssemblyStorageMap;                                        //0x1fc
    ULONG SystemDefaultActivationContextData;                               //0x200
    ULONG SystemAssemblyStorageMap;                                         //0x204
    ULONG MinimumStackCommit;                                               //0x208
    ULONG SparePointers[4];                                                 //0x20c
    ULONG SpareUlongs[5];                                                   //0x21c
    ULONG WerRegistrationData;                                              //0x230
    ULONG WerShipAssertPtr;                                                 //0x234
    ULONG pUnused;                                                          //0x238
    ULONG pImageHeaderHash;                                                 //0x23c
    union
    {
        ULONG TracingFlags;                                                 //0x240
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x240
            ULONG CritSecTracingEnabled:1;                                  //0x240
            ULONG LibLoaderTracingEnabled:1;                                //0x240
            ULONG SpareTracingBits:29;                                      //0x240
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
    ULONG TppWorkerpListLock;                                               //0x250
    struct LIST_ENTRY32 TppWorkerpList;                                     //0x254
    ULONG WaitOnAddressHashTable[128];                                      //0x25c
    ULONG TelemetryCoverageHeader;                                          //0x45c
    ULONG CloudFileFlags;                                                   //0x460
    ULONG CloudFileDiagFlags;                                               //0x464
    CHAR PlaceholderCompatibilityMode;                                      //0x468
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
    ULONG LeapSecondData;                                                   //0x470
    union
    {
        ULONG LeapSecondFlags;                                              //0x474
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x474
            ULONG Reserved:31;                                              //0x474
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x478
} PEB32;

//0x8 bytes (sizeof)
struct _CLIENT_ID32
{
    ULONG UniqueProcess;                                                    //0x0
    ULONG UniqueThread;                                                     //0x4
};

//0x18 bytes (sizeof)
struct _ACTIVATION_CONTEXT_STACK32
{
    ULONG ActiveFrame;                                                      //0x0
    struct LIST_ENTRY32 FrameListCache;                                     //0x4
    ULONG Flags;                                                            //0xc
    ULONG NextCookieSequenceNumber;                                         //0x10
    ULONG StackId;                                                          //0x14
};

//0x4 bytes (sizeof)
struct _PROCESSOR_NUMBER
{
    USHORT Group;                                                           //0x0
    UCHAR Number;                                                           //0x2
    UCHAR Reserved;                                                         //0x3
};

//0x4e0 bytes (sizeof)
struct _GDI_TEB_BATCH32
{
    ULONG Offset:31;                                                        //0x0
    ULONG HasRenderingCommand:1;                                            //0x0
    ULONG HDC;                                                              //0x4
    ULONG Buffer[310];                                                      //0x8
}; 

//0x1000 bytes (sizeof)
typedef struct _TEB32
{
    struct _NT_TIB32 NtTib;                                                 //0x0
    ULONG EnvironmentPointer;                                               //0x1c
    struct _CLIENT_ID32 ClientId;                                           //0x20
    ULONG ActiveRpcHandle;                                                  //0x28
    ULONG ThreadLocalStoragePointer;                                        //0x2c
    ULONG ProcessEnvironmentBlock;                                          //0x30
    ULONG LastErrorValue;                                                   //0x34
    ULONG CountOfOwnedCriticalSections;                                     //0x38
    ULONG CsrClientThread;                                                  //0x3c
    ULONG Win32ThreadInfo;                                                  //0x40
    ULONG User32Reserved[26];                                               //0x44
    ULONG UserReserved[5];                                                  //0xac
    ULONG WOW32Reserved;                                                    //0xc0
    ULONG CurrentLocale;                                                    //0xc4
    ULONG FpSoftwareStatusRegister;                                         //0xc8
    ULONG ReservedForDebuggerInstrumentation[16];                           //0xcc
    ULONG SystemReserved1[26];                                              //0x10c
    CHAR PlaceholderCompatibilityMode;                                      //0x174
    UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x175
    CHAR PlaceholderReserved[10];                                           //0x176
    ULONG ProxiedProcessId;                                                 //0x180
    struct _ACTIVATION_CONTEXT_STACK32 _ActivationStack;                    //0x184
    UCHAR WorkingOnBehalfTicket[8];                                         //0x19c
    LONG ExceptionCode;                                                     //0x1a4
    ULONG ActivationContextStackPointer;                                    //0x1a8
    ULONG InstrumentationCallbackSp;                                        //0x1ac
    ULONG InstrumentationCallbackPreviousPc;                                //0x1b0
    ULONG InstrumentationCallbackPreviousSp;                                //0x1b4
    UCHAR InstrumentationCallbackDisabled;                                  //0x1b8
    UCHAR SpareBytes[23];                                                   //0x1b9
    ULONG TxFsContext;                                                      //0x1d0
    struct _GDI_TEB_BATCH32 GdiTebBatch;                                    //0x1d4
    struct _CLIENT_ID32 RealClientId;                                       //0x6b4
    ULONG GdiCachedProcessHandle;                                           //0x6bc
    ULONG GdiClientPID;                                                     //0x6c0
    ULONG GdiClientTID;                                                     //0x6c4
    ULONG GdiThreadLocalInfo;                                               //0x6c8
    ULONG Win32ClientInfo[62];                                              //0x6cc
    ULONG glDispatchTable[233];                                             //0x7c4
    ULONG glReserved1[29];                                                  //0xb68
    ULONG glReserved2;                                                      //0xbdc
    ULONG glSectionInfo;                                                    //0xbe0
    ULONG glSection;                                                        //0xbe4
    ULONG glTable;                                                          //0xbe8
    ULONG glCurrentRC;                                                      //0xbec
    ULONG glContext;                                                        //0xbf0
    ULONG LastStatusValue;                                                  //0xbf4
    struct _STRING32 StaticUnicodeString;                                   //0xbf8
    WCHAR StaticUnicodeBuffer[261];                                         //0xc00
    ULONG DeallocationStack;                                                //0xe0c
    ULONG TlsSlots[64];                                                     //0xe10
    struct LIST_ENTRY32 TlsLinks;                                           //0xf10
    ULONG Vdm;                                                              //0xf18
    ULONG ReservedForNtRpc;                                                 //0xf1c
    ULONG DbgSsReserved[2];                                                 //0xf20
    ULONG HardErrorMode;                                                    //0xf28
    ULONG Instrumentation[9];                                               //0xf2c
    struct _GUID ActivityId;                                                //0xf50
    ULONG SubProcessTag;                                                    //0xf60
    ULONG PerflibData;                                                      //0xf64
    ULONG EtwTraceData;                                                     //0xf68
    ULONG WinSockData;                                                      //0xf6c
    ULONG GdiBatchCount;                                                    //0xf70
    union
    {
        struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0xf74
        ULONG IdealProcessorValue;                                          //0xf74
        struct
        {
            UCHAR ReservedPad0;                                             //0xf74
            UCHAR ReservedPad1;                                             //0xf75
            UCHAR ReservedPad2;                                             //0xf76
            UCHAR IdealProcessor;                                           //0xf77
        };
    };
    ULONG GuaranteedStackBytes;                                             //0xf78
    ULONG ReservedForPerf;                                                  //0xf7c
    ULONG ReservedForOle;                                                   //0xf80
    ULONG WaitingOnLoaderLock;                                              //0xf84
    ULONG SavedPriorityState;                                               //0xf88
    ULONG ReservedForCodeCoverage;                                          //0xf8c
    ULONG ThreadPoolData;                                                   //0xf90
    ULONG TlsExpansionSlots;                                                //0xf94
    ULONG MuiGeneration;                                                    //0xf98
    ULONG IsImpersonating;                                                  //0xf9c
    ULONG NlsCache;                                                         //0xfa0
    ULONG pShimData;                                                        //0xfa4
    ULONG HeapData;                                                         //0xfa8
    ULONG CurrentTransactionHandle;                                         //0xfac
    ULONG ActiveFrame;                                                      //0xfb0
    ULONG FlsData;                                                          //0xfb4
    ULONG PreferredLanguages;                                               //0xfb8
    ULONG UserPrefLanguages;                                                //0xfbc
    ULONG MergedPrefLanguages;                                              //0xfc0
    ULONG MuiImpersonation;                                                 //0xfc4
    union
    {
        volatile USHORT CrossTebFlags;                                      //0xfc8
        USHORT SpareCrossTebBits:16;                                        //0xfc8
    };
    union
    {
        USHORT SameTebFlags;                                                //0xfca
        struct
        {
            USHORT SafeThunkCall:1;                                         //0xfca
            USHORT InDebugPrint:1;                                          //0xfca
            USHORT HasFiberData:1;                                          //0xfca
            USHORT SkipThreadAttach:1;                                      //0xfca
            USHORT WerInShipAssertCode:1;                                   //0xfca
            USHORT RanProcessInit:1;                                        //0xfca
            USHORT ClonedThread:1;                                          //0xfca
            USHORT SuppressDebugMsg:1;                                      //0xfca
            USHORT DisableUserStackWalk:1;                                  //0xfca
            USHORT RtlExceptionAttached:1;                                  //0xfca
            USHORT InitialThread:1;                                         //0xfca
            USHORT SessionAware:1;                                          //0xfca
            USHORT LoadOwner:1;                                             //0xfca
            USHORT LoaderWorker:1;                                          //0xfca
            USHORT SkipLoaderInit:1;                                        //0xfca
            USHORT SpareSameTebBits:1;                                      //0xfca
        };
    };
    ULONG TxnScopeEnterCallback;                                            //0xfcc
    ULONG TxnScopeExitCallback;                                             //0xfd0
    ULONG TxnScopeContext;                                                  //0xfd4
    ULONG LockCount;                                                        //0xfd8
    LONG WowTebOffset;                                                      //0xfdc
    ULONG ResourceRetValue;                                                 //0xfe0
    ULONG ReservedForWdf;                                                   //0xfe4
    ULONGLONG ReservedForCrt;                                               //0xfe8
    struct _GUID EffectiveContainerId;                                      //0xff0
} TEB32;

typedef struct _CLIENT_ID
{
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
  NTSTATUS ExitStatus;
  PVOID TebBaseAddress;
  CLIENT_ID ClientId;
  KAFFINITY AffinityMask;
  LONG Priority;
  LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

#define CountRelocationEntries(dwBlockSize)		\
	(dwBlockSize -								\
	sizeof(BASE_RELOCATION_BLOCK)) /			\
	sizeof(BASE_RELOCATION_ENTRY)

    typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION_WOW64
{
    NTSTATUS ExitStatus;
    ULONG64  PebBaseAddress;
    ULONG64  AffinityMask;
    LONG BasePriority;
    ULONG64  UniqueProcessId;
    ULONG64  InheritedFromUniqueProcessId;

} PROCESS_BASIC_INFORMATION_WOW64, *PPROCESS_BASIC_INFORMATION_WOW64;

#define CountRelocationEntries(dwBlockSize)     \
    (dwBlockSize -                              \
    sizeof(BASE_RELOCATION_BLOCK)) /            \
    sizeof(BASE_RELOCATION_ENTRY)

typedef enum _SUBSYSTEM_INFORMATION_TYPE {
  SubsystemInformationTypeWin32,
  SubsystemInformationTypeWSL,
  MaxSubsystemInformationType
} SUBSYSTEM_INFORMATION_TYPE, *PSUBSYSTEM_INFORMATION_TYPE;


class HollowingInterface
{
public:
    HollowingInterface(const std::string& targetPath, const std::string& payloadPath) :
        _targetFilePath(targetPath), _payloadFilePath(payloadPath), _targetProcessInformation(CreateSuspendedTargetProcess()),
        _payloadBuffer(ReadFileContents(payloadPath, _payloadBufferSize)),
        _isTarget64Bit(IsProcess64Bit(_targetProcessInformation.hProcess)), _isPayload64Bit(IsPEFile64Bit(_payloadBuffer)),
        _hollowed(false)
    { }

    ~HollowingInterface()
    {
        delete[] _payloadBuffer;

        // If the hollowing was not successful, then we terminate the target process
        if (!_hollowed)
        {
            TerminateProcess(_targetProcessInformation.hProcess, 0);
        }
        
        CloseHandle(_targetProcessInformation.hProcess);
        CloseHandle(_targetProcessInformation.hThread);
    }

    virtual void hollow() = 0;

protected:
    std::string _targetFilePath;
    std::string _payloadFilePath;
    PROCESS_INFORMATION _targetProcessInformation;
    PBYTE _payloadBuffer;
    DWORD _payloadBufferSize;
    bool _isTarget64Bit;
    bool _isPayload64Bit;
    bool _hollowed;

    PROCESS_INFORMATION CreateSuspendedTargetProcess()
    {
        STARTUPINFOA startupInfo;
        PROCESS_INFORMATION processInformation;

        ZeroMemory(&startupInfo, sizeof(startupInfo));
        startupInfo.cb = sizeof(startupInfo);
        ZeroMemory(&processInformation, sizeof(processInformation));

        if (0 == CreateProcessA(nullptr, const_cast<LPSTR>(_targetFilePath.c_str()),
            nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &startupInfo,
            &processInformation))
        {
            throw HollowingException("Could not create the target process!");
        }

        return processInformation;
    }

    PEB64 Read64BitProcessPEB(HANDLE process)
    {
        CONTEXT threadContext;
        threadContext.ContextFlags = CONTEXT_ALL;

        if (0 == GetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            throw HollowingException("An error occured while getting the target's thread context!");
        }
        
        PEB64 processPEB;
        SIZE_T readBytes = 0;

        if (0 == ReadProcessMemory(process, reinterpret_cast<PVOID>(threadContext.Rdx), &processPEB, sizeof(processPEB), &readBytes)
            || 0 == readBytes)
        {
            throw HollowingException("An error occured while reading the target's PEB!");
        }

        return processPEB;
    }
    
    PEB32 Read32BitProcessPEB(HANDLE process)
    {
        PEB32 processPEB;
        WOW64_CONTEXT threadContext;
        threadContext.ContextFlags = WOW64_CONTEXT_INTEGER;

        if (0 == Wow64GetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            throw HollowingException("An error occured while getting the target's thread context!");
        }

        if (0 == ReadProcessMemory(_targetProcessInformation.hProcess, reinterpret_cast<PVOID>(threadContext.Ebx), &processPEB, sizeof(processPEB), nullptr))
        {
            throw HollowingException("An error occured while reading the target's PEB!");
        }

        return processPEB;
    }

    PBYTE ReadFileContents(const std::string& filePath, DWORD& readBytesAmount)
    {
        HANDLE fileHandle = CreateFileA(filePath.c_str(), GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, nullptr);
        if (INVALID_HANDLE_VALUE == fileHandle)
        {
            throw FileException("Could not open the given file's path!");
        }

        DWORD fileSize = GetFileSize(fileHandle, nullptr);
        PBYTE fileContents = new BYTE[fileSize];
        ReadFile(fileHandle, fileContents, fileSize, &readBytesAmount, nullptr);

        if (0 == CloseHandle(fileHandle))
        {
            throw FileException("Could not close the file's handle!");
        }
        
        return fileContents;
    }

    virtual void WriteTargetProcessHeaders(PVOID targetBaseAddress, PBYTE sourceFileContents) = 0;
    virtual void UpdateTargetProcessEntryPoint(PVOID newEntryPointAddress) = 0;
    virtual PIMAGE_DATA_DIRECTORY GetPayloadDirectoryEntry(DWORD directoryID) = 0;
    virtual PIMAGE_SECTION_HEADER FindTargetProcessSection(const std::string& sectionName) = 0;
    virtual void RelocateTargetProcess(ULONGLONG baseAddressesDelta, PVOID processBaseAddress) = 0;
    virtual void ProcessTargetRelocationBlock(PBASE_RELOCATION_BLOCK baseRelocationBlock, PBASE_RELOCATION_ENTRY blockEntries,
        PVOID processBaseAddress, ULONGLONG baseAddressesDelta) = 0;
    virtual void UpdateBaseAddressInTargetPEB(PVOID processNewBaseAddress) = 0;

    DWORD SectionCharacteristicsToMemoryProtections(DWORD characteristics)
    {
        if (IMAGE_SCN_MEM_EXECUTE & characteristics && IMAGE_SCN_MEM_READ & characteristics && IMAGE_SCN_MEM_WRITE & characteristics)
        {
            return PAGE_EXECUTE_READWRITE;
        }
        if (IMAGE_SCN_MEM_EXECUTE & characteristics && IMAGE_SCN_MEM_READ & characteristics)
        {
            return PAGE_EXECUTE_READ;
        }
        if (IMAGE_SCN_MEM_READ & characteristics && IMAGE_SCN_MEM_WRITE & characteristics)
        {
            return PAGE_READWRITE;
        }
        if (IMAGE_SCN_MEM_READ & characteristics)
        {
            return PAGE_READONLY;
        }
        if (IMAGE_SCN_MEM_EXECUTE & characteristics)
        {
            return PAGE_EXECUTE;
        }

        return 0;
    }

    virtual ULONG GetProcessSubsystem(HANDLE process) = 0;
    virtual WORD GetPEFileSubsystem(const PBYTE fileBuffer) = 0;

    virtual bool AreProcessesCompatible() = 0;

    PVOID ReallocateTargetProcessMemory(unsigned int newMemorySize);

    bool IsWindows64Bit()
    {
    #ifdef _WIN64
        return true;
    #else
        BOOL runningUnderWOW64 = FALSE;

        if (0 == IsWow64Process(GetCurrentProcess(), &runningUnderWOW64))
        {
           throw HollowingException("An error occured while checking if the current process is running under WOW64!");
        }

        return TRUE == runningUnderWOW64;
    #endif
    }

    bool IsProcess64Bit(const HANDLE processHandle)
    {
        BOOL runningUnderWOW64 = FALSE;

        if (0 == IsWow64Process(processHandle, &runningUnderWOW64))
        {
            throw HollowingException("An error occured while checking if the current process is running under WOW64!");
        }

        return (runningUnderWOW64) ? false : IsWindows64Bit();
    }

    bool IsPEFile64Bit(const PBYTE fileBuffer)
    {
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer);
        // The offset of the FileHeader field is the same for 64- and 32-bit PE files, so it doesn't matter which version of IMAGE_NT_HEADERS we use.
        PIMAGE_FILE_HEADER fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(fileBuffer + dosHeader->e_lfanew + offsetof(IMAGE_NT_HEADERS64, FileHeader));

        return IMAGE_FILE_MACHINE_AMD64 == fileHeader->Machine;
    }
};

#endif